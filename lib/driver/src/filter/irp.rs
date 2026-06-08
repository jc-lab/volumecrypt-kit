//! IRP_MJ_READ / IRP_MJ_WRITE interception and async dispatch into the crypto
//! pipeline. Other major functions are passed through to the lower device.

use vck_common::VckResult;

use crate::filter::context::FilterContext;

/// Intercept a read IRP: forward down-stack, then decrypt the returned buffer
/// for sectors within the encrypted span on completion.
pub fn on_read(ctx: &FilterContext) -> VckResult<()> {
    let _ = ctx;
    todo!("hook IRP_MJ_READ completion -> CryptoPipeline::decrypt_read")
}

/// Intercept a write IRP: encrypt the buffer for sectors within the encrypted
/// span, then forward down-stack.
pub fn on_write(ctx: &FilterContext) -> VckResult<()> {
    let _ = ctx;
    todo!("encrypt -> forward IRP_MJ_WRITE")
}

/// Pass-through for all other major functions.
pub fn pass_through(ctx: &FilterContext) -> VckResult<()> {
    let _ = ctx;
    todo!("IoSkipCurrentIrpStackLocation + IoCallDriver")
}
