//! `VolumeFilterDriver`: attaches/detaches the filter device to a target volume
//! device stack (IoAttachDeviceToDeviceStackSafe and friends).

use alloc::sync::Arc;

use vck_common::VckResult;

use crate::{filter::context::FilterContext, registry::AttachedVolume};

pub struct VolumeFilterDriver {
    // TODO(driver): hold the WDM driver object / device object handles.
    _private: (),
}

impl VolumeFilterDriver {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Create a filter device object and attach it above `volume`'s device.
    pub fn attach(&self, volume: Arc<AttachedVolume>) -> VckResult<Arc<FilterContext>> {
        let _ = volume;
        todo!("create filter DO + IoAttachDeviceToDeviceStackSafe")
    }

    /// Detach and tear down the filter device.
    pub fn detach(&self, ctx: &FilterContext) -> VckResult<()> {
        let _ = ctx;
        todo!("IoDetachDevice + IoDeleteDevice")
    }
}

impl Default for VolumeFilterDriver {
    fn default() -> Self {
        Self::new()
    }
}
