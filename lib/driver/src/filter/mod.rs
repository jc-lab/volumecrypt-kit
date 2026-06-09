//! Volume filter: attach/detach above a target volume stack, per-volume
//! context, and IRP interception (size-query rewrite + read/write offset shift).

pub mod context;
pub mod io;
pub mod irp;
pub mod manager;

pub use context::FilterContext;
pub use io::handle_filter_irp;
pub use irp::pass_through;
pub use manager::{attach_filter, attach_filter_to_device, attach_filter_unbound,
    detach_filter, filter_bind_volume};
