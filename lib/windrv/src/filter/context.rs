//! Per-volume filter device context.

use alloc::sync::Arc;

use crate::registry::AttachedVolume;

pub struct FilterContext {
    pub volume: Arc<AttachedVolume>,
}

impl FilterContext {
    pub fn new(volume: Arc<AttachedVolume>) -> Self {
        Self { volume }
    }
}
