//! Creation and recovery; a corrupt referenced tree never permits root rollback.
use super::super::{
    disk::{Disk, PAGE},
    memory::{Map, PageSet},
    tree,
};
use super::{format::MAGIC, Core, Policy, Root, Stats};
use anyhow::{ensure, Result};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};
impl Core {
    pub fn create(disk: Arc<dyn Disk>, size: u64, policy: Policy) -> Result<Self> {
        ensure!(size > 0 && size % 512 == 0, "invalid packed virtual size");
        let root = Root {
            generation: 1,
            map_root: 0,
            objects_root: 0,
            next_id: 1,
            size,
            uuid: *uuid::Uuid::new_v4().as_bytes(),
            map: Map::new(),
            objects: Map::new(),
            pages: PageSet::new(),
            data_counts: Map::new(),
            segments: Map::new(),
            encoded_bytes: 0,
            aligned_bytes: 0,
        };
        disk.write(0, &root.encode())?;
        disk.write(PAGE as u64, &[0; PAGE])?;
        disk.barrier()?;
        Ok(Self {
            async_data: false,
            writes: Arc::new(super::super::writeback::ReadCache::default()),
            disk,
            roots: [Some(Arc::new(root)), None],
            current: 0,
            working: None,
            working_blocks: 0,
            map_delta: Map::new(),
            object_delta: Map::new(),
            policy,
            pending: Arc::new(Map::new()),
            poison: Arc::new(std::sync::Mutex::new(None)),
            dedupe: HashMap::new(),
            encoders: super::super::encode::Pool::default(),
            prepared: None,
            publisher: None,
            publication: None,
            cleaner: None,
            punching: None,
            cleaner_rotate: false,
            tree_cache: tree::Cache::default(),
            output_buffer: Vec::new(),
            data_writer: None,
            punched: BTreeSet::new(),
            warm_cursor: 0,
            readers: Vec::new(),
            stats: Stats::default(),
        })
    }
    pub fn open(disk: Arc<dyn Disk>, policy: Policy) -> Result<Self> {
        let mut headers = Vec::new();
        for slot in 0..2 {
            let mut b = [0; PAGE];
            disk.read((slot * PAGE) as u64, &mut b)?;
            if tree::valid(&b) {
                ensure!(&b[..8] == MAGIC, "invalid packed magic");
                headers.push((tree::get64(&b, 24), slot, b));
            }
        }
        headers.sort_by_key(|h| h.0);
        ensure!(!headers.is_empty(), "no valid packed superblock");
        let current = headers.last().unwrap().1;
        let mut roots = [None, None];
        // Never fall back when a checksum-valid root references corrupt metadata.
        for (_, slot, b) in headers {
            roots[slot] = Some(Arc::new(Root::decode(disk.as_ref(), &b)?));
        }
        if let (Some(a), Some(b)) = (&roots[0], &roots[1]) {
            ensure!(
                a.uuid == b.uuid && a.size == b.size,
                "packed superblocks disagree"
            );
        }
        Ok(Self {
            async_data: false,
            writes: Arc::new(super::super::writeback::ReadCache::default()),
            disk,
            roots,
            current,
            working: None,
            working_blocks: 0,
            map_delta: Map::new(),
            object_delta: Map::new(),
            policy,
            pending: Arc::new(Map::new()),
            poison: Arc::new(std::sync::Mutex::new(None)),
            dedupe: HashMap::new(),
            encoders: super::super::encode::Pool::default(),
            prepared: None,
            publisher: None,
            publication: None,
            cleaner: None,
            punching: None,
            cleaner_rotate: false,
            tree_cache: tree::Cache::default(),
            output_buffer: Vec::new(),
            data_writer: None,
            punched: BTreeSet::new(),
            warm_cursor: 0,
            readers: Vec::new(),
            stats: Stats::default(),
        })
    }
}
