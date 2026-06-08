//! `vck-sample-driver`: the JVCK sample kernel driver (builds to a `.sys`).
//!
//! Wires the sample `VckVolumeProvider` into the `vck-driver` framework.
#![no_std]
#![allow(non_snake_case)]

extern crate alloc;

mod provider;

pub use provider::VckVolumeProvider;

use core::panic::PanicInfo;

use wdk_sys::{DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING};

// TODO(sample): set the kernel global allocator (e.g. wdk_alloc::WdkAllocator)
// so `alloc` types work in the driver.

/// Kernel driver entry point.
///
/// # Safety
/// Called by the kernel with valid driver object / registry path pointers.
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(
    driver: *mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let _ = (driver, registry_path);
    // TODO(sample):
    //   1. create the control device (vck_driver::device::ControlDevice::create)
    //   2. read the ACPI handover (vck_driver::handover::read_handover::<VckHandoverPayload>)
    //      -> copy VMK to protected memory, zeroize ACPI buffer
    //   3. register PnP notifications; on OS volume arrival call
    //      VckVolumeProvider::on_attach
    //   4. set IRP_MJ_DEVICE_CONTROL -> ioctl::dispatch with VckVolumeProvider auth
    todo!("DriverEntry: init control device, handover, PnP, IOCTL dispatch")
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    vck_driver::debug::panic_print(info)
}
