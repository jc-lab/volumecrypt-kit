//! Per-volume filter device context.

use alloc::sync::Arc;

use crate::{crypto::pipeline::CryptoPipeline, registry::AttachedVolume};

pub struct FilterContext {
    pub volume: Arc<AttachedVolume>,
    /// Present only for the AES-XTS high-level path.
    pub pipeline: Option<CryptoPipeline>,
    // TODO(driver): lower device object pointer, filter device object pointer.
}

impl FilterContext {
    pub fn new(volume: Arc<AttachedVolume>, pipeline: Option<CryptoPipeline>) -> Self {
        Self { volume, pipeline }
    }
}
