<!--
SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>

SPDX-License-Identifier: Apache-2.0
-->

# volumecrypt-kit

Windows용 **볼륨 투명 암호화 키트**입니다. Rust + WDK 커널 필터 드라이버, UEFI 로더,
Go SDK/CLI로 구성되며, 트레이트 구현만으로 자신만의 볼륨 암호화 제품을 만들 수 있습니다.

- **알고리즘**: AES-256-XTS (섹터 = XTS tweak). AES-NI는 런타임 감지.
- **점진적 암호화**: 라이브 볼륨을 백그라운드 sweep로 암호화하며, 진행 위치(`encrypted_offset`)를
  영속화해 재부팅 후 이어서 진행합니다.
- **두 가지 볼륨 경로**
  - **Data Volume**: OS 부팅 후 IOCTL 로 attach → 암호화. UEFI 불필요.
  - **OS(System) Volume**: 파일시스템 shrink → footer 메타데이터 기록 → 암호화.
    이후 UEFI 로더가 부팅 윈도우에서 `EFI_BLOCK_IO`를 후킹해 복호화하고, 커널 드라이버가
    런타임 복호화를 이어받습니다.
- **High/Low level**: 기본 제공 **JVCK 메타데이터 포맷**을 쓰거나(VMK만 입력), 트레이트를 직접
  구현해 자체 온디스크 포맷·키 관리로 교체할 수 있습니다.

> 키트의 모든 메커니즘(필터, 암복호 파이프라인, 핸드오버)은 `lib/`에 있고, `sample/`은
> 트레이트 구현·설정 로딩만 담당하는 참조 구현입니다.

## 저장소 구조

```
lib/      Rust 라이브러리 — common(공통/JVCK), windrv(커널 드라이버), loader(UEFI 로더)
sdk/      Go 유저스페이스 SDK (DeviceIoControl + msgpack 클라이언트)
sample/   참조 구현 — common, windrv(드라이버), loader(UEFI), app(Go CLI)
testing/  VM 기반 E2E 테스트 자산 (test-foundry, OVMF, recipes)
```

## 빠른 시작

커널/UEFI 빌드에는 WEDK 툴체인과 msys2 셸이 필요합니다(자세한 내용은
[docs/build-and-test.md](docs/build-and-test.md)).

```bash
make test          # 호스트 단위테스트 (vck-common, cargo test)
make build-driver  # 커널 드라이버 (.sys, 서명까지)
make build-loader  # UEFI 로더 (.efi)
make build-app     # Go CLI (vck-app.exe)

# 실제 VM E2E (test-foundry)
make test-vm-os-encrypt   # OS 볼륨 암호화 → 로더 경유 부팅 → 런타임 복호화
make test-vm-data-volume  # 데이터 볼륨 attach → encrypt → 상태 확인
```

## 문서

- [docs/architecture.md](docs/architecture.md) — 구성 요소, 크레이트 레이아웃, I/O 모델, IOCTL, Go SDK
- [docs/jvck-format.md](docs/jvck-format.md) — 기본 JVCK 온디스크 메타데이터 포맷과 키 파생
- [docs/boot-and-encryption-flow.md](docs/boot-and-encryption-flow.md) — OS/Data 볼륨 암호화·부팅·런타임 흐름
- [docs/build-and-test.md](docs/build-and-test.md) — 빌드 환경(WEDK), Makefile 타깃, VM 테스트

## 라이선스

Apache-2.0. © 2026 JC-Lab.
