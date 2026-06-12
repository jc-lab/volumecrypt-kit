<!--
SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>

SPDX-License-Identifier: Apache-2.0
-->

# 빌드 / 테스트

## 환경

- **msys2** 로그인 셸을 기본 셸로 사용합니다. `make`는 msys2에서 실행해야 합니다.
- **WEDK**(Windows EWDK 등 커널 빌드 툴체인)가 마운트되어 있어야 합니다. 드라이버 빌드 전
  WEDK 빌드 환경 설정 스크립트를 source 합니다(Makefile의 `LOAD_ENV`).
- 커널/UEFI 크레이트는 **호스트에서 빌드되지 않습니다**(wdk-sys / uefi 타깃). 순수 로직은
  `vck-common`(std)에서 `cargo test`로, 커널 동작은 VM에서 검증합니다.
- **AES-NI 주의**: 드라이버/로더 RUSTFLAGS에 `-C target-feature=+aes`를 넣지 마세요. `aes` 크레이트가
  런타임 감지로 하드웨어 AES를 쓰며, `+aes` 강제는 커널 스택 오버플로(`0x7F`)를 유발합니다.
- **panic 전략**: `panic="abort"`는 워크스페이스 `Cargo.toml`의 `[profile.dev]`/`[profile.release]`에만
  둡니다. cargo가 `test`/`bench` 프로파일에서는 무시하므로 `make test`(=`cargo test -p vck-common`)가
  그대로 동작합니다.

## Makefile 타깃

| 명령 | 대상 | 환경 |
|---|---|---|
| `make build-common` / `make test` | `vck-common` 빌드 / 호스트 단위테스트 | 호스트(msvc) |
| `make build-driver` | `vck-sample-driver` → `.sys` (서명까지) | WEDK, `x86_64-pc-windows-msvc` |
| `make build-loader` | `vck-sample-loader` → `.efi` | `x86_64-unknown-uefi` |
| `make build-app` | `vck-app.exe` (Go) | 호스트 |
| `make test-vm-driver-load` | 드라이버 로드 + `vck-app status` | win11 VM |
| `make test-vm-data-volume` | 데이터 볼륨 attach→encrypt→상태 | win11 VM |
| `make test-vm-os-handover` | 로더→드라이버 핸드오버 E2E | win11 VM |
| `make test-vm-os-encrypt` | OS 볼륨 암호화→로더 경유 부팅→런타임 복호화 E2E | win11 VM |

드라이버 빌드 검증은 반드시 드라이버 바이너리 크레이트(`vck-sample-driver`)를 통해 합니다
(`cargo build -p vck-driver` 단독은 `wdk-sys` 바인딩이 비어 빌드되지 않음).

예시(msys2 셸):

```bash
C:/msys64/usr/bin/bash.exe -lc 'cd /d/workspace/volumecrypt-kit; make build-driver'
```

## VM 테스트 (test-foundry)

VM 안에서 드라이버 로드, EFI 파일 변경, 재부팅 등 모든 작업을 수행합니다. recipe는
`testing/recipes/<name>/<name>.yaml`이며 Makefile 타깃이 이를 실행합니다. VM 셋업은 한 번만 수행하면
되고(`vm-setup`), 이후에는 `test` 명령만 사용합니다.

> test-foundry: https://github.com/jc-lab/test-foundry — headless 실행이 필요합니다.

존재하는 recipe: `driver-load`, `driver-load-dev`, `data-volume`, `os-volume-prepare`, `os-handover`,
`os-encrypt`, `os-encrypt-dev`.

### 디버그 로그 (debug.log)

recipe yaml에서 QEMU `isa-debugcon`(I/O 포트 `0xe9`)을 파일로 캡처하면 드라이버/로더의 진단 출력을
얻습니다.

```yaml
qemu:
  extra_args:
    - "-chardev"
    - "file,id=debugout,path=${{ output.dir }}/debug.log"
    - "-device"
    - "isa-debugcon,iobase=0xe9,chardev=debugout"
```

드라이버와 로더는 동일한 `vck_log!` 매크로로 `{timestamp} vck-driver: …` / `{timestamp} vck-loader: …`
형식의 줄을 이 포트에 출력합니다(`lib/windrv/src/debug.rs`, `lib/loader/src/debug.rs`).

### 크래시 덤프 분석 (cdb)

VM이 bugcheck하면 recipe의 panic 핸들러가 `memory.dmp`를 남깁니다. WinDbg의 `cdb`로 분석합니다.

```bat
set _NT_SYMBOL_PATH=srv*C:\ProgramData\dbg\sym*https://msdl.microsoft.com/download/symbols
cdb.exe -z memory.dmp -c "!analyze -v; q"
```

드라이버 심볼은 `target/x86_64-pc-windows-msvc/release/vck_sample_driver.pdb`로 매칭됩니다
(`.sympath+`로 추가).
