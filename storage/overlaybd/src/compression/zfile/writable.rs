//! Append-only live ZFile. The sidecar is a checksummed commit log, not an
//! exchange format. Sealing writes the ordinary ZFile index/trailer in place.
use super::*;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

const BLOCK: usize = 4096;
const LOG_MAGIC: &[u8; 8] = b"OBDZLOG2";
const MAX_COMMIT: usize = 16 * 1024 * 1024;

pub fn journal_path(path: &Path) -> PathBuf {
    path.with_extension("zlog")
}
pub fn codec(path: &Path) -> Result<Option<&'static str>> {
    let f = File::open(path)?;
    let mut h = [0u8; HEADER_TRAILER_SPACE];
    f.read_exact_at(&mut h, 0)?;
    let h = HeaderTrailer::decode_from_512(&h)?;
    if !h.verify_magic() {
        return Ok(None);
    }
    ensure!(h.is_valid(&h.encode_512()?), "invalid live zfile header");
    Ok(Some(match h.opt.algo {
        CompressOptions::LZ4 => "lz4",
        CompressOptions::ZSTD => "zstd",
        _ => bail!("unsupported upper codec"),
    }))
}

struct State {
    lengths: Vec<u32>,
    offsets: Vec<u64>,
    committed: usize,
    end: u64,
    log_end: u64,
    index_end: u64,
    compressor: Box<dyn Compressor>,
    encoded: Vec<u8>,
    sealed: bool,
    failed: bool,
}
/// Prepared without holding the mapping or append-state lock. Only published
/// under the LSMT write lock, so flush never observes half-published mappings.
pub(crate) struct PreparedAppend {
    encoded: Vec<u8>,
    lengths: Vec<u32>,
    input_len: usize,
}
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct WriteProfile {
    pub encode_ns: u64,
    pub append_ns: u64,
    pub commit_ns: u64,
    pub encoded_blocks: u64,
}
pub struct WritableZFile {
    encoder: Mutex<Box<dyn Compressor>>,
    encode_ns: AtomicU64,
    append_ns: AtomicU64,
    commit_ns: AtomicU64,
    encoded_blocks: AtomicU64,
    data: File,
    index: File,
    log: File,
    ht: HeaderTrailer,
    state: Mutex<State>,
}
impl WritableZFile {
    /// Convert a freshly initialized, empty log-structured LSMT upper only.
    pub fn initialize(path: &Path, index: &Path, algorithm: &str) -> Result<()> {
        let algo = match algorithm {
            "lz4" => CompressOptions::LZ4,
            "zstd" => CompressOptions::ZSTD,
            _ => bail!("invalid upper compression"),
        };
        let source = File::open(path)?;
        ensure!(
            source.metadata()?.len() == BLOCK as u64,
            "compression initialization requires an empty upper"
        );
        let mut header = [0u8; BLOCK];
        source.read_exact_at(&mut header, 0)?;
        use zerocopy::FromBytes;
        type LsmtHeader = crate::lsmt::format::HeaderTrailer;
        let raw = LsmtHeader::read_from_bytes(&header[..std::mem::size_of::<LsmtHeader>()])
            .map_err(|_| anyhow::anyhow!("invalid source upper header"))?;
        crate::index_file::validate_rw_header_pair_paths(
            path,
            Some(index),
            raw.virtual_size.get(),
            crate::index_file::RwLayout::LogStructured,
        )?;
        let data = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(journal_path(path))?;
        let mut ht = HeaderTrailer::new();
        ht.set_header();
        ht.set_data_file();
        ht.opt = CompressOptions::new(algo, BLOCK as u32, 1);
        ht.set_digest_enable();
        ht.digest = crc32c(&ht.encode_512()?);
        data.write_all_at(&ht.encode_512()?, 0)?;
        log.write_all_at(LOG_MAGIC, 0)?;
        let file = Self {
            encoder: Mutex::new(create_compressor(&CompressArgs::new(ht.opt))?),
            encode_ns: AtomicU64::new(0),
            append_ns: AtomicU64::new(0),
            commit_ns: AtomicU64::new(0),
            encoded_blocks: AtomicU64::new(0),
            data,
            index: OpenOptions::new().read(true).write(true).open(index)?,
            log,
            state: Mutex::new(State {
                lengths: Vec::new(),
                offsets: Vec::new(),
                committed: 0,
                end: 512,
                log_end: 8,
                index_end: 0,
                compressor: create_compressor(&CompressArgs::new(ht.opt))?,
                encoded: Vec::new(),
                sealed: false,
                failed: false,
            }),
            ht,
        };
        file.append(0, &header)?;
        file.commit()?;
        Ok(())
    }
    pub fn open(path: &Path, index: &Path) -> Result<Self> {
        let data = OpenOptions::new().read(true).write(true).open(path)?;
        let index = OpenOptions::new().read(true).write(true).open(index)?;
        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_path(path))?;
        let mut h = [0; 512];
        data.read_exact_at(&mut h, 0)?;
        let ht = HeaderTrailer::decode_from_512(&h)?;
        ensure!(
            ht.verify_magic()
                && ht.is_valid(&h)
                && ht.is_header()
                && !ht.is_header_overwrite()
                && ht.opt.dict_size == 0
                && ht.opt.block_size == BLOCK as u32
                && ht.opt.verify == 1,
            "invalid compressed upper header"
        );
        let mut magic = [0; 8];
        log.read_exact_at(&mut magic, 0)?;
        ensure!(&magic == LOG_MAGIC, "invalid compressed upper journal");
        let mut lengths = Vec::new();
        let mut pos = 8u64;
        let size = log.metadata()?.len();
        let mut index_end = 0u64;
        while pos + 4 <= size {
            let mut n = [0; 4];
            log.read_exact_at(&mut n, pos)?;
            let n = u32::from_le_bytes(n) as usize;
            ensure!((24..=MAX_COMMIT).contains(&n), "invalid journal frame size");
            if pos + 4 + n as u64 > size {
                break;
            }
            let mut frame = vec![0; n];
            log.read_exact_at(&mut frame, pos + 4)?;
            let crc = u32::from_le_bytes(frame[n - 4..].try_into()?);
            ensure!(
                crc32c(&frame[..n - 4]) == crc,
                "compressed upper journal checksum mismatch"
            );
            let count = u64::from_le_bytes(frame[..8].try_into()?);
            let next_index_end = u64::from_le_bytes(frame[8..16].try_into()?);
            let index_len = u32::from_le_bytes(frame[16..20].try_into()?) as usize;
            ensure!(
                index_len <= n - 24 && (n - 24 - index_len).is_multiple_of(4),
                "invalid journal frame layout"
            );
            ensure!(
                count == lengths.len() as u64
                    && next_index_end
                        == index_end
                            .checked_add(index_len as u64)
                            .context("index overflow")?,
                "invalid journal sequence"
            );
            let index_start = n - 4 - index_len;
            for b in frame[20..index_start].chunks_exact(4) {
                let len = u32::from_le_bytes(b.try_into()?);
                ensure!(
                    len > 4 && len as usize <= BLOCK + 128,
                    "invalid encoded block size"
                );
                lengths.push(len);
            }
            // upper.index is a rebuildable LSMT cache; the WAL is authoritative.
            index.write_all_at(&frame[index_start..n - 4], index_end)?;
            index_end = next_index_end;
            pos += 4 + n as u64;
        }
        ensure!(
            !lengths.is_empty()
                && index_end >= BLOCK as u64
                && index_end <= index.metadata()?.len(),
            "missing or truncated committed upper index"
        );
        let mut end = 512u64;
        let mut offsets = Vec::with_capacity(lengths.len());
        for &len in &lengths {
            offsets.push(end);
            end = end.checked_add(len as u64).context("upper size overflow")?;
        }
        ensure!(
            end <= data.metadata()?.len(),
            "truncated committed upper data"
        );
        // Bind the recovered journal to this data/index pair before truncation.
        use zerocopy::FromBytes;
        type LsmtHeader = crate::lsmt::format::HeaderTrailer;
        let mut first = vec![0; lengths[0] as usize];
        data.read_exact_at(&mut first, 512)?;
        let n = first.len();
        ensure!(
            crc32c_salt(&first[..n - 4]) == u32::from_le_bytes(first[n - 4..].try_into()?),
            "upper header block checksum mismatch"
        );
        let decoder = create_compressor(&CompressArgs::new(ht.opt))?;
        let mut decoded = [0; BLOCK];
        ensure!(
            decoder.decompress(&first[..n - 4], &mut decoded)? == BLOCK,
            "invalid LSMT header block"
        );
        let dh = LsmtHeader::read_from_bytes(&decoded[..std::mem::size_of::<LsmtHeader>()])
            .map_err(|_| anyhow::anyhow!("invalid LSMT data header"))?;
        index.read_exact_at(&mut decoded, 0)?;
        let ih = LsmtHeader::read_from_bytes(&decoded[..std::mem::size_of::<LsmtHeader>()])
            .map_err(|_| anyhow::anyhow!("invalid LSMT index header"))?;
        ensure!(
            dh.verify_magic()
                && ih.verify_magic()
                && dh.uuid == ih.uuid
                && dh.virtual_size == ih.virtual_size
                && !dh.is_hybrid_rw()
                && !dh.is_sparse_rw(),
            "compressed upper data/journal identity mismatch"
        );
        // Only uncommitted append tails are discarded. Existing committed blocks
        // are immutable, so recovery never rewrites their contents.
        data.set_len(end)?;
        index.set_len(index_end)?;
        log.set_len(pos)?;
        let committed = lengths.len();
        Ok(Self {
            encoder: Mutex::new(create_compressor(&CompressArgs::new(ht.opt))?),
            encode_ns: AtomicU64::new(0),
            append_ns: AtomicU64::new(0),
            commit_ns: AtomicU64::new(0),
            encoded_blocks: AtomicU64::new(0),
            data,
            index,
            log,
            state: Mutex::new(State {
                lengths,
                offsets,
                committed,
                end,
                log_end: pos,
                index_end,
                compressor: create_compressor(&CompressArgs::new(ht.opt))?,
                encoded: Vec::new(),
                sealed: false,
                failed: false,
            }),
            ht,
        })
    }
    pub fn write_profile(&self) -> WriteProfile {
        WriteProfile {
            encode_ns: self.encode_ns.load(Ordering::Relaxed),
            append_ns: self.append_ns.load(Ordering::Relaxed),
            commit_ns: self.commit_ns.load(Ordering::Relaxed),
            encoded_blocks: self.encoded_blocks.load(Ordering::Relaxed),
        }
    }
    pub(crate) fn prepare_append(&self, bytes: &[u8]) -> Result<PreparedAppend> {
        let started = Instant::now();
        let mut compressor = self
            .encoder
            .lock()
            .map_err(|_| anyhow::anyhow!("encoder lock poisoned"))?;
        let count = bytes.len().div_ceil(BLOCK);
        let mut prepared = PreparedAppend {
            encoded: Vec::with_capacity(count * (BLOCK + 128)),
            lengths: Vec::with_capacity(count),
            input_len: bytes.len(),
        };
        let mut output = [0u8; BLOCK + 128];
        let mut padded = [0u8; BLOCK];
        for chunk in bytes.chunks(BLOCK) {
            let src = if chunk.len() == BLOCK {
                chunk
            } else {
                padded.fill(0);
                padded[..chunk.len()].copy_from_slice(chunk);
                &padded
            };
            let n = compress_data(compressor.as_mut(), src, &mut output, true)?;
            prepared.encoded.extend_from_slice(&output[..n]);
            prepared.lengths.push(n as u32);
        }
        self.encode_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        self.encoded_blocks
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(prepared)
    }
    fn append(&self, offset: u64, bytes: &[u8]) -> Result<usize> {
        self.append_prepared(offset, self.prepare_append(bytes)?)
    }
    pub(crate) fn append_prepared(&self, offset: u64, prepared: PreparedAppend) -> Result<usize> {
        let started = Instant::now();
        let mut s = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("upper lock poisoned"))?;
        ensure!(
            !s.failed && !s.sealed,
            "compressed upper is sealed or failed"
        );
        ensure!(
            offset == s.lengths.len() as u64 * BLOCK as u64,
            "compressed upper requires aligned append"
        );
        if prepared.input_len == 0 {
            return Ok(0);
        }
        s.failed = true;
        let write_start = s.end - s.encoded.len() as u64;
        if s.encoded.is_empty() {
            s.encoded = prepared.encoded;
        } else {
            s.encoded.extend_from_slice(&prepared.encoded);
        }
        for n in prepared.lengths {
            let end = s.end;
            s.offsets.push(end);
            s.end += n as u64;
            s.lengths.push(n);
        }
        if s.encoded.len() >= MAX_COALESCED_READ_SIZE {
            self.data.write_all_at(&s.encoded, write_start)?;
            s.encoded.clear();
        }
        s.failed = false;
        self.append_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        Ok(prepared.input_len)
    }
    fn commit(&self) -> Result<()> {
        let started = Instant::now();
        let mut s = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("upper lock poisoned"))?;
        ensure!(!s.failed, "compressed upper failed");
        if s.sealed {
            self.data.sync_all()?;
            return Ok(());
        }
        s.failed = true;
        if !s.encoded.is_empty() {
            self.data
                .write_all_at(&s.encoded, s.end - s.encoded.len() as u64)?;
            s.encoded.clear();
        }
        self.data.sync_all()?;
        let index_end = self.index.metadata()?.len();
        ensure!(index_end >= s.index_end, "upper index shrank during commit");
        let total = s.lengths.len();
        // First publish every encoded block boundary, then mapping deltas.
        // Each bounded WAL frame is independently checksummed and replayable.
        loop {
            let end = (s.committed + 65536).min(total);
            let index_len = if end == total {
                (index_end - s.index_end).min(1024 * 1024) as usize
            } else {
                0
            };
            let mut frame = Vec::with_capacity(24 + (end - s.committed) * 4 + index_len);
            frame.extend_from_slice(&(s.committed as u64).to_le_bytes());
            frame.extend_from_slice(&(s.index_end + index_len as u64).to_le_bytes());
            frame.extend_from_slice(&(index_len as u32).to_le_bytes());
            for len in &s.lengths[s.committed..end] {
                frame.extend_from_slice(&len.to_le_bytes());
            }
            let start = frame.len();
            frame.resize(start + index_len, 0);
            self.index.read_exact_at(&mut frame[start..], s.index_end)?;
            frame.extend_from_slice(&crc32c(&frame).to_le_bytes());
            self.log
                .write_all_at(&(frame.len() as u32).to_le_bytes(), s.log_end)?;
            self.log.write_all_at(&frame, s.log_end + 4)?;
            s.log_end += 4 + frame.len() as u64;
            s.committed = end;
            s.index_end += index_len as u64;
            if end == total && s.index_end == index_end {
                break;
            }
        }
        self.log.sync_all()?;
        s.index_end = index_end;
        s.failed = false;
        self.commit_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        Ok(())
    }
    pub fn finish(&self) -> Result<()> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("upper lock poisoned"))?;
        ensure!(
            !s.failed && !s.sealed,
            "compressed upper already sealed or failed"
        );
        s.failed = true;
        if !s.encoded.is_empty() {
            self.data
                .write_all_at(&s.encoded, s.end - s.encoded.len() as u64)?;
            s.encoded.clear();
        }
        let mut raw = Vec::with_capacity(s.lengths.len() * 4);
        for n in &s.lengths {
            raw.extend_from_slice(&n.to_le_bytes());
        }
        self.data.write_all_at(&raw, s.end)?;
        let mut ht = self.ht.clone();
        ht.set_trailer();
        ht.set_sealed();
        ht.set_digest_enable();
        ht.index_offset = s.end;
        ht.index_size = s.lengths.len() as u64;
        ht.original_file_size = s.lengths.len() as u64 * BLOCK as u64;
        ht.index_crc = crc32c(&raw);
        ht.digest = 0;
        ht.digest = crc32c(&ht.encode_512()?);
        self.data
            .write_all_at(&ht.encode_512()?, s.end + raw.len() as u64)?;
        self.data.sync_all()?;
        s.sealed = true;
        s.failed = false;
        Ok(())
    }
}
#[async_trait]
impl VirtualFile for WritableZFile {
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let mut out = vec![0; len];
        let n = self.read_at_into(offset, &mut out).await?;
        out.truncate(n);
        Ok(Bytes::from(out))
    }
    async fn read_at_into(&self, offset: u64, dst: &mut [u8]) -> Result<usize> {
        let s = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("upper lock poisoned"))?;
        ensure!(!s.failed, "compressed upper failed");
        let size = s.lengths.len() as u64 * BLOCK as u64;
        let n = dst.len().min(size.saturating_sub(offset) as usize);
        let mut done = 0;
        let mut encoded = PooledBatchBuffer::take();
        let mut decoded = [0u8; BLOCK];
        let mut cached_start = 0u64;
        let mut cached_end = 0u64;
        while done < n {
            let at = offset + done as u64;
            let block = (at / BLOCK as u64) as usize;
            let len = s.lengths[block] as usize;
            let physical = s.offsets[block];
            if physical < cached_start || physical + len as u64 > cached_end {
                let end_block =
                    ((offset + n as u64).div_ceil(BLOCK as u64) as usize).min(s.lengths.len());
                let mut last = block + 1;
                while last < end_block
                    && s.offsets[last] + s.lengths[last] as u64 - physical
                        <= MAX_COALESCED_READ_SIZE as u64
                {
                    last += 1;
                }
                cached_start = physical;
                cached_end = s.offsets[last - 1] + s.lengths[last - 1] as u64;
                encoded.resize((cached_end - cached_start) as usize, 0);
                let persisted_end = s.end - s.encoded.len() as u64;
                let disk_len = cached_end.min(persisted_end).saturating_sub(cached_start) as usize;
                if disk_len != 0 {
                    self.data
                        .read_exact_at(&mut encoded[..disk_len], cached_start)?;
                }
                if cached_end > persisted_end {
                    let tail_start = cached_start.max(persisted_end) - persisted_end;
                    encoded[disk_len..].copy_from_slice(
                        &s.encoded[tail_start as usize..(cached_end - persisted_end) as usize],
                    );
                }
            }
            let start = (physical - cached_start) as usize;
            let encoded = &encoded[start..start + len];
            ensure!(
                crc32c_salt(&encoded[..len - 4])
                    == u32::from_le_bytes(encoded[len - 4..len].try_into()?),
                "compressed upper block checksum mismatch"
            );
            let start = at as usize % BLOCK;
            let take = (BLOCK - start).min(n - done);
            if start == 0 && take == BLOCK {
                ensure!(
                    s.compressor
                        .decompress(&encoded[..len - 4], &mut dst[done..done + BLOCK])?
                        == BLOCK,
                    "invalid decoded upper block size"
                );
            } else {
                ensure!(
                    s.compressor.decompress(&encoded[..len - 4], &mut decoded)? == BLOCK,
                    "invalid decoded upper block size"
                );
                dst[done..done + take].copy_from_slice(&decoded[start..start + take]);
            }
            done += take;
        }
        Ok(n)
    }
    async fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
        self.append(offset, data)
    }
    async fn size(&self) -> Result<u64> {
        Ok(self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("upper lock poisoned"))?
            .lengths
            .len() as u64
            * BLOCK as u64)
    }
    async fn sync(&self) -> Result<()> {
        self.commit()
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}
