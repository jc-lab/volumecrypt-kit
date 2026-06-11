# SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
#
# SPDX-License-Identifier: Apache-2.0

SHELL := /bin/bash
.ONESHELL:
# .SHELLFLAGS := -lc

.PHONY: build-common build-driver build-driver-package build-crypto-test-driver build-loader build-app test $(TEST_VM_DIR) test-vm-smoke test-vm-driver-load test-vm-os-volume-prepare test-vm-data-volume test-vm-crypto-test test-vm-os-handover test-vm-os-encrypt clean

TEST_VM_DIR = .testfoundry/win11
LOAD_ENV := source ./.ci/scripts/load-wdk-env.sh

build-common:
	cargo build -p vck-common

testing/signing/MyTestDriverCert.cer: ./testing/signing/generate.sh
	OUT_DIR=./testing/signing ./testing/signing/generate.sh

# Driver-only rustflags: link the static CRT. panic=abort comes from the
# workspace [profile] (test-safe; see Cargo.toml).
# On x64 the OS saves/restores the full thread context (including XMM/AES-NI)
# on every context switch, so AES-NI is safe at PASSIVE_LEVEL without any
# explicit save/restore wrapper.
DRIVER_RUSTFLAGS = -C target-feature=+crt-static

# Built in release: unoptimized debug frames overflow the small (~12 KiB)
# kernel stack on the metadata/crypto path.
build-driver: testing/signing/MyTestDriverCert.cer
	$(LOAD_ENV)
	RUSTFLAGS="$(DRIVER_RUSTFLAGS)" cargo build --release -p vck-sample-driver --target x86_64-pc-windows-msvc
	powershell -NoProfile -ExecutionPolicy Bypass -File ./testing/signing/sign-driver.ps1 -InputPath ./target/x86_64-pc-windows-msvc/release/vck_sample_driver.dll -OutputPath ./testing/artifacts/vck-sample-driver.sys
	cp ./sample/windrv/vck-sample-driver.inf ./testing/artifacts/vck-sample-driver.inf
	powershell -NoProfile -ExecutionPolicy Bypass -File ./testing/signing/sign-driver-package.ps1 \
	  -DriverSys ./testing/artifacts/vck-sample-driver.sys \
	  -DriverInf ./testing/artifacts/vck-sample-driver.inf \
	  -OutputDir ./testing/artifacts/vck-driver-pkg

build-crypto-test-driver: testing/signing/MyTestDriverCert.cer
	$(LOAD_ENV)
	RUSTFLAGS="$(DRIVER_RUSTFLAGS)" cargo build --release -p vck-crypto-test-driver --target x86_64-pc-windows-msvc
	powershell -NoProfile -ExecutionPolicy Bypass -File ./testing/signing/sign-driver.ps1 -InputPath ./target/x86_64-pc-windows-msvc/release/vck_crypto_test_driver.dll -OutputPath ./testing/artifacts/vck-crypto-test-driver.sys

build-loader:
	cargo build -p vck-sample-loader --target x86_64-unknown-uefi
	mkdir -p testing/artifacts
	cp ./target/x86_64-unknown-uefi/debug/vck-sample-loader.efi ./testing/artifacts/vck-sample-loader.efi

build-app:
	mkdir -p testing/artifacts
	go build -o ./testing/artifacts/vck-app.exe ./sample/app

test:
	cargo test -p vck-common

$(TEST_VM_DIR): testing/signing/MyTestDriverCert.cer
	test-foundry.exe --vm-name="win11" vm-setup --image ./testing/images/windows-11.yaml

build-driver-package: testing/signing/MyTestDriverCert.cer testing/artifacts/vck-sample-driver.sys testing/artifacts/vck-sample-driver.inf build-driver
	$(LOAD_ENV)
	powershell -NoProfile -ExecutionPolicy Bypass -File ./testing/signing/sign-driver-package.ps1 \
	  -DriverSys ./testing/artifacts/vck-sample-driver.sys \
	  -DriverInf ./testing/artifacts/vck-sample-driver.inf \
	  -OutputDir ./testing/artifacts/vck-driver-pkg

test-vm-smoke: $(TEST_VM_DIR)
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/smoke-guest-exec --test ./testing/recipes/smoke-guest-exec/smoke.yaml

test-vm-driver-load: $(TEST_VM_DIR) build-driver-package build-app
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/driver-load --test ./testing/recipes/driver-load/driver-load.yaml

test-vm-os-volume-prepare: $(TEST_VM_DIR) build-driver-package build-app
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/os-volume-prepare --test ./testing/recipes/os-volume-prepare/os-volume-prepare.yaml

test-vm-data-volume: $(TEST_VM_DIR) build-driver-package build-app
	rm -rf ./testing/results/data-volume
	test-foundry.exe --vm-name=win11 test --headless --output ./testing/results/data-volume --test ./testing/recipes/data-volume/data-volume.yaml

test-vm-crypto-test: $(TEST_VM_DIR) build-crypto-test-driver
	test-foundry.exe  --vm-name=win11 test --headless --output ./testing/results/crypto-test --test ./testing/recipes/crypto-test/crypto-test.yaml

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

clean:
	cargo clean
	go clean ./...
