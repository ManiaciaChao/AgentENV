//! Experimental native compressed upper. No VDO runtime or Hybrid data mapping.
mod core;
mod encode;
mod file;
mod memory;
pub use file::PackedUpper;
mod disk;
mod tree;
pub use core::{Codec, Policy, Stats};
#[cfg(test)]
mod tests;

pub(crate) use disk::{Disk, FileDisk};
