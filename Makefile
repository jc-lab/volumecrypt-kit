SHELL := /bin/bash
# .SHELLFLAGS := -lc

export PATH := /d/programs:/c/Program Files/qemu:/c/Users/User/.cargo/bin:/c/Program Files/Go/bin:$(PATH)

.PHONY: build-common build-driver build-crypto-test-driver build-loader build-app test $(TEST_VM_DIR) test-vm-smoke test-vm-driver-load test-vm-os-volume-prepare test-vm-data-volume test-vm-crypto-test clean

TEST_VM_DIR = .testfoundry/win11

build-common:
	cargo build -p vck-common

testing/signing/MyTestDriverCert.cer: ./testing/signing/generate.sh
	OUT_DIR=./testing/signing ./testing/signing/generate.sh

build-driver: testing/signing/MyTestDriverCert.cer
	MSYS2_ARG_CONV_EXCL="/c" cmd.exe /c "call G:\\BuildEnv\\SetupBuildEnv.cmd && cd /d . && cargo build -p vck-sample-driver --target x86_64-pc-windows-msvc"
	powershell -NoProfile -ExecutionPolicy Bypass -File ./testing/signing/sign-driver.ps1 -InputPath ./target/x86_64-pc-windows-msvc/debug/vck_sample_driver.dll -OutputPath ./testing/artifacts/vck-sample-driver.sys

build-crypto-test-driver: testing/signing/MyTestDriverCert.cer
	MSYS2_ARG_CONV_EXCL="/c" cmd.exe /c "call G:\\BuildEnv\\SetupBuildEnv.cmd && cd /d . && cargo build -p vck-crypto-test-driver --target x86_64-pc-windows-msvc"
	powershell -NoProfile -ExecutionPolicy Bypass -File ./testing/signing/sign-driver.ps1 -InputPath ./target/x86_64-pc-windows-msvc/debug/vck_crypto_test_driver.dll -OutputPath ./testing/artifacts/vck-crypto-test-driver.sys

build-loader:
	cargo build -p vck-sample-loader --target x86_64-unknown-uefi

build-app:
	mkdir -p testing/artifacts
	go build -o ./testing/artifacts/vck-app.exe ./sample/app

test:
	cargo test -p vck-common

$(TEST_VM_DIR): testing/signing/MyTestDriverCert.cer
	test-foundry.exe --vm-name="win11" vm-setup --image ./testing/images/windows-11.yaml

test-vm-smoke: $(TEST_VM_DIR)
	test-foundry.exe --vm-name=win11 test --output ./testing/results/smoke-guest-exec --test ./testing/recipes/smoke-guest-exec/smoke.yaml

test-vm-driver-load: $(TEST_VM_DIR) build-driver build-app
	test-foundry.exe --vm-name=win11 test --output ./testing/results/driver-load --test ./testing/recipes/driver-load/driver-load.yaml

test-vm-os-volume-prepare: $(TEST_VM_DIR) build-app
	test-foundry.exe --vm-name=win11 test --output ./testing/results/os-volume-prepare --test ./testing/recipes/os-volume-prepare/os-volume-prepare.yaml

test-vm-crypto-test: $(TEST_VM_DIR) build-crypto-test-driver
	test-foundry.exe --vm-name=win11 test --output ./testing/results/crypto-test --test ./testing/recipes/crypto-test/crypto-test.yaml

clean:
	cargo clean
	go clean ./...
