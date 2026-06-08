//! Volume filter: attach/detach above a target volume stack, per-volume
//! context, and IRP read/write interception (pass-through for now).

pub mod context;
pub mod irp;
pub mod manager;

pub use context::FilterContext;
pub use irp::pass_through;
pub use manager::{attach_filter, detach_filter};
