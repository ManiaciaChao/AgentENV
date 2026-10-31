//! Page allocation and bounded payload packing for one transaction.
use super::super::{
    disk::{Disk, PAGE},
    tree::{self, Pages},
};
use super::SEGMENT;
use anyhow::{ensure, Result};
use std::{collections::BTreeSet, sync::Arc};
pub(super) struct Allocation {
    pub(super) disk: Arc<dyn Disk>,
    pub(super) free: BTreeSet<u64>,
    pub(super) fragment_budget: u64,
    pub(super) fragment_appends: u64,
    pub(super) end: u64,
    // The open packing page is the last page of output, never a separate copy.
    pub(super) pack: Option<(u64, usize)>,
    pub(super) metadata: u64,
    pub(super) cache: tree::Cache,
    pub(super) created: BTreeSet<u64>,
    pub(super) retired: BTreeSet<u64>,
    pub(super) excluded: Option<u64>,
    pub(super) output: Vec<u8>,
    pub(super) output_offset: u64,
    pub(super) write_calls: u64,
    pub(super) write_bytes: u64,
    pub(super) io_ns: u64,
    pub(super) metadata_io_ns: u64,
    pub(super) queue_wait_ns: u64,
    pub(super) writer: super::super::writeback::Writer,
}
impl Pages for Allocation {
    fn allocate(&mut self) -> u64 {
        self.metadata += 1;
        let p = self.page();
        self.created.insert(p);
        p
    }
    fn disk(&self) -> &dyn Disk {
        self.disk.as_ref()
    }
    fn retire(&mut self, p: u64) {
        self.retired.insert(p);
    }
    fn read_page(&mut self, page: u64, level: u8) -> Result<[u8; PAGE]> {
        let bytes = self.cache.read(self.disk.as_ref(), page, level)?;
        // COW traversal retires a node before reading it. No working traversal
        // will need that physical version again; reader roots use in-memory
        // mappings, and recovery always validates disk pages independently.
        if self.retired.contains(&page) {
            self.cache.invalidate(page);
        }
        Ok(bytes)
    }
    fn write_page(&mut self, page: u64, bytes: &[u8; PAGE]) -> Result<()> {
        self.data_page(page, bytes)?;
        self.cache.insert(page, bytes);
        Ok(())
    }
}
pub(super) struct PackedRun {
    pub(super) offset: u64,
    pub(super) shift_at: usize,
    pub(super) shift: usize,
}
impl PackedRun {
    pub(super) fn at(&self, offset: usize) -> u64 {
        self.offset
            + (offset
                + if offset >= self.shift_at {
                    self.shift
                } else {
                    0
                }) as u64
    }
}
impl Allocation {
    fn page(&mut self) -> u64 {
        if let Some(p) = self.free.pop_first() {
            // A former metadata page may now hold data or a different tree.
            self.cache.invalidate(p);
            p
        } else {
            if self.excluded == Some(self.end * PAGE as u64 / SEGMENT) {
                self.end = (self.end * PAGE as u64 / SEGMENT + 1) * (SEGMENT / PAGE as u64);
            }
            let p = self.end;
            self.end += 1;
            p
        }
    }
    pub(super) fn flush_data(&mut self) -> Result<()> {
        if !self.output.is_empty() {
            self.write_calls += 1;
            self.write_bytes += self.output.len() as u64;
            self.output = self.writer.submit(
                self.output_offset,
                std::mem::take(&mut self.output),
                self.metadata != 0,
            )?;
        }
        Ok(())
    }
    pub(super) fn finish_io(&mut self) -> Result<()> {
        let timings = self.writer.finish()?;
        self.io_ns += timings.data_ns;
        self.metadata_io_ns += timings.metadata_ns;
        self.queue_wait_ns += timings.wait_ns;
        Ok(())
    }
    fn start_page(&mut self, page: u64) -> Result<()> {
        debug_assert!(self.pack.is_none());
        let offset = page * PAGE as u64;
        if !self.output.is_empty()
            && (self.output_offset + self.output.len() as u64 != offset
                || self.output.len() >= super::super::writeback::WRITE_BYTES)
        {
            self.flush_data()?;
        }
        if self.output.is_empty() {
            // Recycled encoder buffers have arbitrary capacities. Geometric
            // growth from those sizes could exceed the writer's 2 MiB limit.
            self.output
                .reserve_exact(super::super::writeback::WRITE_BYTES);
            self.output_offset = offset;
        }
        Ok(())
    }
    fn data_page(&mut self, page: u64, data: &[u8; PAGE]) -> Result<()> {
        self.start_page(page)?;
        self.output.extend_from_slice(data);
        Ok(())
    }
    fn packing_page(&mut self, page: u64) -> Result<()> {
        self.start_page(page)?;
        self.output.resize(self.output.len() + PAGE, 0);
        self.pack = Some((page, 0));
        Ok(())
    }
    pub(super) fn finish_pack(&mut self) -> Result<()> {
        // Padding already exists in the output buffer. Once closed, this page
        // is immutable; start_page may send it to disk while opening the next.
        self.pack = None;
        Ok(())
    }

    // Compression workers already laid out independent objects at 64-byte
    // boundaries. Reserve one contiguous run and hand the allocation to the writer.
    // Fragmented free space uses the per-object path instead of growing forever
    // while ignoring reusable holes. Search work is bounded per batch.
    pub(super) fn packed_batch(
        &mut self,
        bytes: &mut Vec<u8>,
        spans: &[(usize, usize)],
    ) -> Result<Option<PackedRun>> {
        if bytes.is_empty() {
            return Ok(Some(PackedRun {
                offset: 0,
                shift_at: usize::MAX,
                shift: 0,
            }));
        }
        ensure!(
            bytes.len() % PAGE == 0 && bytes.len() as u64 <= SEGMENT,
            "invalid packed batch"
        );
        // A batch may span segments; an individual encoded object may not.
        // Shift only the crossing object and its successors, instead of leaving
        // an almost-full-batch-sized hole at every segment boundary.
        let content_end = spans
            .iter()
            .map(|(at, len)| at + len)
            .max()
            .unwrap_or(bytes.len());
        let layout = |start: u64| {
            let boundary = (SEGMENT - start * PAGE as u64 % SEGMENT) as usize;
            let crossing = spans
                .iter()
                .find(|&&(at, len)| at < boundary && at + len > boundary);
            let (shift_at, shift) =
                crossing.map_or((usize::MAX, 0), |&(at, _)| (at, boundary - at));
            let count = (content_end + shift).div_ceil(PAGE) as u64;
            (shift_at, shift, count)
        };
        // First prefer a complete free run. If none exists, the fallback below
        // bounds how much fragmented space can be deferred for small writes.
        let mut found = None;
        if self.free.len() >= bytes.len() / PAGE {
            let mut run = 0;
            let mut start = 0;
            for &page in self.free.iter().take(4096) {
                if self.excluded == Some(page * PAGE as u64 / SEGMENT) {
                    run = 0;
                    continue;
                }
                if run == 0 || page != start + run {
                    start = page;
                    run = 0;
                }
                run += 1;
                if run as usize * PAGE >= bytes.len() {
                    let (at, shift, count) = layout(start);
                    if run >= count && count as usize * PAGE <= super::super::writeback::WRITE_BYTES
                    {
                        found = Some((start, at, shift, count));
                        break;
                    }
                }
            }
        }
        let (start, shift_at, shift, count) = if let Some(found) = found {
            for page in found.0..found.0 + found.3 {
                self.free.remove(&page);
                self.cache.invalidate(page);
            }
            found
        } else {
            if self.free.len() >= bytes.len() / PAGE && self.excluded.is_none() {
                // Bulk payloads should not turn into thousands of page writes
                // merely because retired tree nodes left small isolated holes.
                // Reserve a bounded amount for metadata/small writes. The cap
                // derives from live bytes, never file length, so overwrites
                // cannot ratchet the reserve upward as the file grows.
                if self.free.len() as u64 >= self.fragment_budget {
                    return Ok(None);
                }
                self.fragment_appends += 1;
            }
            // A cleaner must consolidate into a contiguous destination. Reusing
            // isolated holes would reproduce the very fragmentation it removes.
            // At most one segment is relocated per transaction; foreground I/O
            // still reuses fragmented free pages instead of growing unboundedly.
            let pages_per_segment = SEGMENT / PAGE as u64;
            let (_, _, count) = layout(self.end);
            if let Some(excluded) = self.excluded {
                if self.end / pages_per_segment <= excluded
                    && (self.end + count - 1) / pages_per_segment >= excluded
                {
                    self.end = (excluded + 1) * pages_per_segment;
                }
            }
            let mut start = self.end;
            let (mut at, mut shift, mut count) = layout(start);
            if count as usize * PAGE > super::super::writeback::WRITE_BYTES {
                if self.excluded.is_none() {
                    return Ok(None);
                }
                start = start.next_multiple_of(pages_per_segment);
                (at, shift, count) = layout(start);
            }
            self.end = start + count;
            (start, at, shift, count)
        };
        if shift != 0 {
            bytes.resize(count as usize * PAGE, 0);
            bytes.copy_within(shift_at..content_end, shift_at + shift);
            bytes[shift_at..shift_at + shift].fill(0);
            bytes[content_end + shift..].fill(0);
        }
        self.finish_pack()?;
        self.flush_data()?;
        self.write_calls += 1;
        self.write_bytes += bytes.len() as u64;
        *bytes = self
            .writer
            .submit(start * PAGE as u64, std::mem::take(bytes), false)?;
        Ok(Some(PackedRun {
            offset: start * PAGE as u64,
            shift_at,
            shift,
        }))
    }

    pub(super) fn payload(&mut self, b: &[u8]) -> Result<u64> {
        let n = b.len().next_multiple_of(64);
        if self.pack.is_some_and(|(_, used)| used == PAGE || n == PAGE) {
            self.finish_pack()?;
        }
        if let Some((p, used)) = self.pack {
            if used + n > PAGE {
                let next = p + 1;
                let contiguous = (p * PAGE as u64 / SEGMENT == next * PAGE as u64 / SEGMENT)
                    && self.excluded != Some(next * PAGE as u64 / SEGMENT)
                    && (self.free.contains(&next) || next == self.end);
                if contiguous {
                    self.cache.invalidate(next);
                    if !self.free.remove(&next) {
                        self.end += 1;
                    }
                    let first = PAGE - used;
                    let at = self.output.len() - PAGE + used;
                    self.output[at..].copy_from_slice(&b[..first]);
                    self.finish_pack()?;
                    self.packing_page(next)?;
                    let at = self.output.len() - PAGE;
                    self.output[at..at + b.len() - first].copy_from_slice(&b[first..]);
                    self.pack = Some((next, n - first));
                    return Ok(p * PAGE as u64 + used as u64);
                }
                self.finish_pack()?;
            }
        }
        if self.pack.is_none() {
            let p = self.page();
            self.packing_page(p)?;
        }
        let (p, used) = self.pack.as_mut().unwrap();
        let offset = *p * PAGE as u64 + *used as u64;
        let at = self.output.len() - PAGE + *used;
        self.output[at..at + b.len()].copy_from_slice(b);
        *used += n;
        Ok(offset)
    }
}
