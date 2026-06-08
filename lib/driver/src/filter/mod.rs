//! Volume filter driver stack: attach/detach management, per-volume context,
//! and IRP read/write interception.

pub mod context;
pub mod irp;
pub mod manager;

pub use context::FilterContext;
pub use manager::VolumeFilterDriver;
