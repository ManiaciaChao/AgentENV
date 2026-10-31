//! Optional native compressed upper, directly addressed by guest logical blocks.
//!
//! `file` owns the VirtualFile/lower adapter and its range/flush synchronization;
//! its coordinator is the sole owner of `core::Core`. Private Core children
//! implement format validation, recovery, allocation, transactions and reclamation.
//! Root publication (`publish`) and physical punching (`cleaner`) run workers,
//! but neither owns logical mappings or acknowledges foreground writes.
//!
//! `disk::Disk` isolates physical I/O and durability from these mechanisms. The
//! model disk in `tests` exercises the same protocol under reordered/torn writes.
//! Local `Policy` only selects future encodings; stored objects remain readable
//! across policy changes. No VDO worker or Hybrid mapping is used by this backend.
//!
//! Workspace intent/receipt and directory publication belong to the caller, not
//! to the packed format. ImageFile integration and standard LSMT export stay in
//! OverlayBD; FSKit, CLI and product lifecycle code stay outside this crate.
mod buffer;
mod cleaner;
mod core;
mod disk;
mod encode;
mod file;
mod memory;
mod policy;
mod publish;
mod scheduling;
mod stats;
mod tree;
mod writeback;

pub(crate) use disk::{Disk, FileDisk};
pub use file::PackedUpper;
pub use policy::{Codec, Policy};
pub use stats::Stats;

#[cfg(test)]
mod tests;
