# SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
#
# SPDX-License-Identifier: Apache-2.0

.ONESHELL:
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

.PHONY: build-common build-driver build-driver-package build-loader build-app test test-vm-setup test-vm-smoke test-vm-driver-load test-vm-os-volume-prepare test-vm-data-volume test-vm-data-volume-decrypt test-vm-crypto-test test-vm-os-handover test-vm-os-encrypt clean

TEST_VM_DIR = .testfoundry/win11
LOAD_ENV := source ./.ci/scripts/load-wdk-env.sh

build-common:
	cargo build -p vck-common

testing/signing/MyTestDriverCert.cer: ./testing/signing/generate.sh
	OUT_DIR=./testing/signing ./testing/signing/generate.sh

# Driver-only rustflags: link the static CRT. panic=abort comes from the
# workspace [profile] (test-safe; see Cargo.toml).
#
# Do NOT add -C target-feature=+aes here. The `aes` crate detects AES-NI at
# runtime (via cpufeatures) and dispatches to its hardware backend, so the
# driver already gets hardware AES on x64. Forcing +aes globally lets LLVM
# INLINE the fully-unrolled AES-NI encrypt8/decrypt8 into the deep storage/
# metadata/IOCTL call chain, ballooning kernel stack frames past the (small)
# kernel stack and double-faulting on stack overflow. Keeping the AES-NI code
# behind the crate's runtime-dispatch call boundary bounds those frames.
#
# On x64 the OS saves/restores the full thread context (including XMM/AES-NI)
# on every context switch, so AES-NI is safe at PASSIVE_LEVEL without any
# explicit save/restore wrapper.
DRIVER_RUSTFLAGS = -C target-feature=+crt-static

UEFI_RUSTFLAGS = -C target-feature=-soft-float

# Built in release: unoptimized debug frames overflow the small (~12 KiB)
# kernel stack on the metadata/crypto path.

clippy-driver:
	$(LOAD_ENV)
	RUSTFLAGS="$(DRIVER_RUSTFLAGS)" cargo clippy -p vck-windrv -p vck-sample-driver -- -D warnings

build-driver: testing/signing/MyTestDriverCert.cer
	$(LOAD_ENV)
	RUSTFLAGS="$(DRIVER_RUSTFLAGS)" cargo build -p vck-sample-driver --target x86_64-pc-windows-msvc --release
	powershell -NoProfile -ExecutionPolicy Bypass -File ./testing/signing/sign-driver.ps1 -InputPath ./target/x86_64-pc-windows-msvc/release/vck_sample_driver.dll -OutputPath ./testing/artifacts/vck-sample-driver.sys
	cp ./sample/windrv/vck-sample-driver.inf ./testing/artifacts/vck-sample-driver.inf
	powershell -NoProfile -ExecutionPolicy Bypass -File ./testing/signing/sign-driver-package.ps1 \
	  -DriverSys ./testing/artifacts/vck-sample-driver.sys \
	  -DriverInf ./testing/artifacts/vck-sample-driver.inf \
	  -OutputDir ./testing/artifacts/vck-windrv-pkg

build-loader:
	RUSTFLAGS="$(UEFI_RUSTFLAGS)" cargo build -p vck-sample-loader --target x86_64-unknown-uefi
	mkdir -p testing/artifacts
	cp ./target/x86_64-unknown-uefi/debug/vck-sample-loader.efi ./testing/artifacts/vck-sample-loader.efi

build-app:
	mkdir -p testing/artifacts
	go build -o ./testing/artifacts/vck-app.exe ./sample/app

test:
	cargo test -p vck-common

test-publish:
	$(LOAD_ENV)
	cargo publish -p vck-common --dry-run --locked
	cargo publish -p vck-loader --dry-run --locked
	cargo publish -p vck-windrv --dry-run --locked

$(TEST_VM_DIR): testing/signing/MyTestDriverCert.cer
	test-foundry.exe --vm-name="win11" vm-setup --image ./testing/images/windows-11.yaml

test-vm-setup: $(TEST_VM_DIR)

build-driver-package: testing/signing/MyTestDriverCert.cer testing/artifacts/vck-sample-driver.sys testing/artifacts/vck-sample-driver.inf build-driver
	$(LOAD_ENV)
	powershell -NoProfile -ExecutionPolicy Bypass -File ./testing/signing/sign-driver-package.ps1 \
	  -DriverSys ./testing/artifacts/vck-sample-driver.sys \
	  -DriverInf ./testing/artifacts/vck-sample-driver.inf \
	  -OutputDir ./testing/artifacts/vck-windrv-pkg

test-vm-smoke: $(TEST_VM_DIR)
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/smoke-guest-exec --test ./testing/recipes/smoke-guest-exec/smoke.yaml

test-vm-driver-load: $(TEST_VM_DIR) build-driver-package build-app
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/driver-load --test ./testing/recipes/driver-load/driver-load.yaml

test-vm-os-volume-prepare: $(TEST_VM_DIR) build-driver-package build-app
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/os-volume-prepare --test ./testing/recipes/os-volume-prepare/os-volume-prepare.yaml

test-vm-data-volume: $(TEST_VM_DIR) build-driver-package build-app
	rm -rf ./testing/results/data-volume
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/data-volume --test ./testing/recipes/data-volume/data-volume.yaml

# Data volume encrypt -> detach -> attach -> decrypt round-trip (validates the
# decrypt sweep, persisted state, and the prepare/attach/detach/encrypt/decrypt CLI).
test-vm-data-volume-decrypt: $(TEST_VM_DIR) build-driver-package build-app
	rm -rf ./testing/results/data-volume-decrypt
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/data-volume-decrypt --test ./testing/recipes/data-volume-decrypt/data-volume-decrypt.yaml

# Stage 3h: validate the UEFI loader -> driver ACPI handover end-to-end.
# Prepares the OS volume (shrink/efi/vck.json), installs the loader as
# bootmgfw.efi, reboots through the loader, then checks the driver's debug.log
# for the handover-present line (proves XSDT injection + read_handover work).
test-vm-os-handover: $(TEST_VM_DIR) build-driver build-app build-loader
	rm -rf ./testing/results/os-handover
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/os-handover --test ./testing/recipes/os-handover/os-handover.yaml

# Full OS-volume first-time encryption end-to-end: install driver (Volume
# UpperFilter, boot-start) → reboot → encrypt whole C: → install loader →
# reboot THROUGH loader (Block IO hook decrypts the boot window) → verify boot +
# marker-file integrity. Long-running (encrypts all of C: with soft AES).
test-vm-os-encrypt: $(TEST_VM_DIR) build-driver build-app build-loader
	rm -rf ./testing/results/os-encrypt
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/os-encrypt --test ./testing/recipes/os-encrypt/os-encrypt.yaml

test-vm-driver-load-dev: $(TEST_VM_DIR) build-driver build-app build-loader
	rm -rf ./testing/results/driver-load-dev
	test-foundry.exe --headless --vm-name=win11 test --output ./testing/results/driver-load-dev --test ./testing/recipes/driver-load-dev/driver-load-dev.yaml

test-vm-os-encrypt-dev: $(TEST_VM_DIR) build-driver build-app build-loader
	rm -rf ./testing/results/os-encrypt
	test-foundry.exe --headless --vm-name=win11 test --output ./testing/results/os-encrypt-dev --test ./testing/recipes/os-encrypt-dev/os-encrypt-dev.yaml

clean:
	cargo clean
	go clean ./...
