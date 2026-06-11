// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), wdk_build::ConfigError> {
    wdk_build::configure_wdk_library_build()?;
    // `IoCreateDeviceSecure` is exported via wdmsec.lib (not bound by wdk-sys);
    // link it so the control device can be created with an SDDL descriptor.
    // `dylib` (import library) defers resolution to the final binary link, where
    // the km library search path is provided by the binary crate's wdk-build
    // setup (wdmsec.lib sits beside ntoskrnl.lib in the km/<arch> dir).
    println!("cargo::rustc-link-lib=dylib=wdmsec");
    Ok(())
}
