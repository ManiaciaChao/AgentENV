pub mod cache;
pub mod local;
#[cfg(feature = "full")]
pub mod oss;
#[cfg(feature = "full")]
pub mod registryfs_v2;
pub mod switch;
pub mod tar;

// Backward-compatible path while implementation is aligned to overlaybd registryfs_v2.
#[cfg(feature = "full")]
pub use registryfs_v2 as remote;

pub mod vdo;
