//! Local future-write policy, independent of the encodings already stored on disk.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Codec {
    None,
    Lz4,
    Zstd,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub compression: Codec,
    pub dedupe: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            compression: Codec::Lz4,
            dedupe: false,
        }
    }
}
