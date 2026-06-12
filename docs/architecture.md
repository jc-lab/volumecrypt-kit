<!--
SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>

SPDX-License-Identifier: Apache-2.0
-->

# 아키텍처

`volumecrypt-kit`은 Rust + WDK 기반 Windows 볼륨 암호화 키트입니다. 키트 본체(`lib/`)가 볼륨 필터,
암복호 파이프라인, 점진적 암호화 상태 머신, UEFI↔드라이버 핸드오버 등 모든 메커니즘을 제공하고,
통합자(`sample/`)는 트레이트 구현과 설정 로딩만 담당합니다.

암호화 포맷은 두 수준으로 쓸 수 있습니다.

- **High-level**: 키트가 제공하는 **JVCK 메타데이터 포맷**([jvck-format.md](jvck-format.md))을 그대로 사용.
  VMK(Volume Master Key)만 입력하면 FVEK·진행상태·지오메트리를 메타데이터에서 복원합니다.
- **Low-level**: `VolumeProvider`/`IoHooks`/`EncryptedOffsetStore`를 직접 구현해 자체 온디스크 포맷과
  키 관리로 교체. 키트는 필터·I/O 라우팅만 담당합니다.

## 저장소 / 언어 경계

| 언어 | 범위 | 빌드 단위 |
|---|---|---|
| Rust | `lib/{common,windrv,loader}`, `sample/{common,windrv,loader}` | Cargo workspace |
| Go | `sdk/`, `sample/app` | Go module (`github.com/jc-lab/volumecrypt-kit`) |

```
lib/common   공통 타입·에러, JVCK 메타데이터 포맷, 핸드오버 트레이트, SectorIo/EncryptedOffsetStore 트레이트
lib/windrv   커널 드라이버 프레임워크 (필터 스택, per-volume 암복호/sweep 스레드, IOCTL, AES-XTS)
lib/loader   UEFI 로더 프레임워크 (EFI_BLOCK_IO 후킹, UEFI 변수 핸드오버, 체인로드)
sdk          Go 클라이언트 (DeviceIoControl + msgpack)
sample/*     위 트레이트의 참조 구현 + Go CLI
```

> 두 언어는 `DeviceIoControl` + msgpack 경계로만 통신하며 서로의 런타임에 의존하지 않습니다.
> `lib/windrv/src/ioctl/`(Rust)과 `sdk/`(Go)는 같은 IOCTL 명세의 양쪽 표현입니다.

## lib/common

전 컴포넌트가 공유하는 기반 코드입니다.

- `error.rs` — `VckError` / `VckResult<T>`
- `types.rs` — `Guid`, `VolumeId`, `SectorRange`, `EncryptedOffset`
- `cpu.rs` — `has_aes_ni()` (CPUID.01H:ECX[25]) — 드라이버/로더 공용
- `store.rs` — `SectorIo`, `EncryptedOffsetStore` 트레이트
- `xts.rs` — `XtsVolumeCipher`: 공유 AES-256-XTS. 8블록 병렬 경로로 처리량을 높입니다.
- `jvck/` — 기본 JVCK 메타데이터 포맷(키 파생, CRC/HMAC, store). 자세히는 [jvck-format.md](jvck-format.md).
- `handover/payload.rs` — `HandoverPayload` 트레이트 + msgpack `encode/decode_payload`.

**tweak 규약**: 모든 섹터 번호는 **데이터 영역 상대 섹터**(`rel = lba - offset_sector`)입니다.
`rel == 0`이 암호화 대상의 첫 섹터이며, header/footer 메타데이터 영역은 포함하지 않습니다.
로더와 드라이버가 동일한 `XtsVolumeCipher`를 쓰므로 양쪽 암복호가 구성상 일치합니다.

```rust
pub struct EncryptedOffset {
    pub sector: u64,        // 이 값 이전까지 암호화 완료 (데이터 영역 상대 섹터)
    pub total_sectors: u64, // 암호화 대상 총 섹터 (= 데이터 영역 크기)
}

// 핸드오버 페이로드: 직렬화 + 전송용 UEFI 변수 식별자(구체 값은 sample이 지정)
pub trait HandoverPayload: Serialize + DeserializeOwned {
    const VAR_NAME: &'static str;
    const VAR_GUID: [u8; 16];
}
```

## lib/windrv (커널 드라이버 프레임워크)

볼륨 필터 드라이버 스택을 관리하고, 섹터 단위 AES-XTS 암복호와 점진적 암호화 sweep를 수행합니다.

**컨트롤 디바이스**: 로드 시 `\Device\VolumeCryptKitSample` + `\DosDevices\VolumeCryptKitSample`
(= `\\.\VolumeCryptKitSample`)을 만들고, Go SDK가 `CreateFile`로 열어 `DeviceIoControl`로 통신합니다.
디바이스는 `IoCreateDeviceSecure`(SDDL)로 생성되어 write 핸들은 관리자만 열 수 있습니다.

**I/O 모델 (per-volume 스레드)**: cipher가 바인딩된 필터마다 `PsCreateSystemThread`로 **per-volume
시스템 스레드**가 하나 생성됩니다(bind 시 생성 / rebind 시 swap / detach 시 정지). 이 스레드 하나가
그 볼륨의 사용자 READ/WRITE IRP와 백그라운드 sweep 배치를 **직렬로** 처리하므로 sweep↔IRP 데이터
레이스가 구조적으로 없습니다.

- READ: 필터가 IRP를 큐에 넣고 `STATUS_PENDING` 반환 → 스레드가 자체 NonPagedPool 버퍼로 하위
  디바이스에서 동기 read → `rel < encrypted_offset` 섹터를 복호화 → 원본 MDL로 복사 → 완료.
- WRITE: 원본을 자체 버퍼로 복사 → `rel < encrypted_offset` 섹터를 암호화 → 하위에 기록 → 완료.
- 메타데이터 영역(데이터 영역 밖) I/O와 cipher 없는 볼륨은 그대로 pass-through.

> 커널 스택이 작으므로(콜아웃 32KiB, 워커 스레드 ~24KiB) 드라이버/로더 RUSTFLAGS에
> `-C target-feature=+aes`를 **넣지 않습니다**. `aes` 크레이트가 AES-NI를 런타임 감지·디스패치하며,
> `+aes`를 강제하면 언롤된 AES-NI가 깊은 콜체인에 인라인되어 스택 오버플로(`0x7F` double-fault)를 냅니다.

**핵심 타입**

- `VolumeAttachRegistry` — attach된 모든 볼륨(`AttachedVolume`)을 NT 디바이스 경로로 추적.
- `AttachSource` — `Handover`(OS 볼륨, 부팅 자동 attach) / `Ioctl`(데이터 볼륨, 런타임 attach).
- `IoConfig` — `Passthrough` / `Encrypted{cipher: Option<Box<dyn VolumeCipher>>, offset_sector,
  encrypted_offset, offset_store}`(고수준, cipher를 sample이 실어 보냄; `None`은 size-hiding만 하는
  provisional attach) / `Custom{io_hooks,...}`(저수준).
- `EncryptionEngine`(`offset/engine.rs`) — 점진적 암복호 상태 머신 + 배치 sweep + offset 영속화.
- `VolumeProvider` 트레이트 — 볼륨 bind 정책(`on_attach(&AttachContext) -> IoConfig`). object-safe·동기로,
  `DriverEntry`에서 `set_volume_provider(&PROVIDER)`로 전역 등록되어 **부팅 OS 볼륨 mount(PnP 콜백)와
  IOCTL attach** 양쪽에서 호출됩니다. 프레임워크는 메타데이터를 직접 복호화하지 않습니다 —
  `AttachContext`가 볼륨 데이터 경로 위의 owning `SectorIo`(`io`)와 VMK를 주면, sample이 그 위에서
  메타데이터(+ vendor-specific data)를 읽어 **자기 알고리즘으로 복호화**하고 `VolumeCipher`를 만들어
  `IoConfig`로 돌려줍니다.
- `IoctlAuthorization` 트레이트 — IOCTL 권한 정책 훅(sample 구현).

### IOCTL

`FILE_DEVICE_VCK = 0x22`, `METHOD_BUFFERED`. 입출력 버퍼는 모두 msgpack입니다. 읽기 전용 조회는
`FILE_READ_ACCESS`, 상태 변경은 `FILE_WRITE_ACCESS`(→ 비관리자는 write 핸들을 못 열어 OS가 거부).
값은 `lib/windrv/src/ioctl/codes.rs`와 `sdk/ioctl.go`가 **컴파일 타임 단언**으로 동기화됩니다.

| IOCTL | 값 | 용도 |
|---|---|---|
| `GET_STATUS` | `0x0022_6000` | 볼륨 상태 조회 (read) |
| `START_ENCRYPT` | `0x0022_a004` | 점진적 암호화 시작 |
| `START_DECRYPT` | `0x0022_a008` | 점진적 복호화 시작 |
| `GET_PROGRESS` | `0x0022_600c` | 진행률 스냅샷 (read, 논블로킹) |
| `PAUSE` | `0x0022_a010` | sweep 일시정지 |
| `JVCK_ATTACH` | `0x0022_a014` | 데이터 볼륨 attach 2단계(메타데이터 읽기→활성화) |
| `VCK_DETACH` | `0x0022_a018` | 데이터 볼륨 detach |
| `JVCK_PREPARE` | `0x0022_a01c` | 데이터/OS 볼륨 attach 1단계(필터 부착 + size hiding) |
| `PAUSE_OS_VOLUME` | `0x0022_a020` | OS 볼륨 sweep 정지(셧다운 시 드라이버 내부 사용) |
| `DETACH_ALL_VOLUMES` | `0x0022_a024` | 모든 데이터 볼륨 detach(셧다운/언로드 시) |
| `BENCH_AES` | `0x0022_6028` | 인커널 AES-XTS throughput 벤치 (read) |
| `LIST_VOLUMES` | `0x0022_602c` | attach된 볼륨 열거 (read, 입력 없음) |

`GET_STATUS`/`START_*`/`GET_PROGRESS`/`PAUSE`/`DETACH`/`LIST_VOLUMES`는 포맷과 무관한 공통 IOCTL입니다
(attach된 볼륨을 `volume_path`로 지정). 자체 포맷을 쓰는 통합자는 attach만 별도로 구현하고 나머지 공통
IOCTL을 재사용할 수 있습니다.

## lib/loader (UEFI 로더 프레임워크)

`uefi` 크레이트 기반. OS 볼륨이 암호화된 상태에서 Windows를 부팅하기 위한 "부팅 윈도우" 복호화를 담당합니다.

- 메커니즘만 제공 — sample 로더가 흐름을 직접 구동합니다: `vck_loader::init()`(시작 배너 + SSE/XMM
  제어비트 설정), `locate_block_io_volume`(복호화 없이 OS 볼륨 BlockIO를 `SectorIo`로 open),
  `BlockIoHookEngine::new(HookGeometry, Box<dyn VolumeCipher>)` + `install()`, `install_handover`,
  `chainload_next`. sample이 메타데이터를 **스스로 복호화**하고 cipher를 만들어 hook에 넘깁니다.
- `hook/block_io.rs` — `EFI_BLOCK_IO_PROTOCOL.ReadBlocks`를 후킹해 대상 파티션 데이터 영역을 투명 복호화.
  (`block_io2.rs`의 `EFI_BLOCK_IO2` async 경로는 미후킹 — Windows 부팅은 동기 BlockIo 경로 사용.)
- `handover.rs::install_handover` — 페이로드를 `P::VAR_NAME`/`P::VAR_GUID` UEFI 런타임 변수로
  `SetVariable`(`BOOTSERVICE_ACCESS|RUNTIME_ACCESS`) 발행.
- `cpu.rs` — 시작 시 AES-NI 지원 로깅 + (지원 시) SSE/XMM 제어비트(`CR0.MP/EM`, `CR4.OSFXSR/OSXMMEXCPT`) 설정.
- `chainload.rs` — 다음 OS 로더(`bootmgfw.os.efi`) 체인로드.

## 핸드오버 (UEFI → 드라이버)

OS 볼륨은 메타데이터가 볼륨 footer에 있으므로, 로더는 드라이버에 **VMK와 대상 partition_guid만**
전달합니다. 전송은 **UEFI 런타임 변수**입니다.

1. 로더: `SetVariable(VAR_NAME, VAR_GUID, msgpack(payload))`.
2. 드라이버: `ExGetFirmwareEnvironmentVariable`로 읽어 `decode_payload` → VMK를 보호 메모리로 복사 후
   변수 버퍼 zeroize.

변수 이름/GUID와 페이로드 구조는 **sample**(`vck-sample-common`의 `VckHandoverPayload`)이 지정합니다
(`HANDOVER_VAR_NAME = "VckHandover"`). 키트는 직렬화·변수 발행/읽기 헬퍼만 제공합니다.

> 과거 ACPI 커스텀 테이블/XSDT 주입 방식은 제거되었습니다. 커널
> `ZwQuerySystemInformation(SystemFirmwareTableInformation,"ACPI")`가 `STATUS_NOT_IMPLEMENTED`라
> 드라이버가 ACPI 테이블을 읽을 수 없었기 때문입니다.

## Go SDK (sdk)

`DeviceIoControl`을 msgpack 직렬화로 래핑한 타입 안전 클라이언트입니다.

- `client.go` — `Open`/`Close` + `Attach`/`Detach`/`GetStatus`/`StartEncrypt`/`StartDecrypt`/`Pause`/
  `ListVolumes`/`BenchAes` 등.
- `types.go` — `VolumeStatus`, `ProgressEvent`, `JvckVolume{Prepare,Attach}Request/Response`,
  `VolumeListResponse`, `EncryptionState` 등 (Rust `ioctl/types.rs`와 필드/태그 일치).
- `ioctl.go` — IOCTL 코드 상수(위 표와 동일) + `deviceControl[Req,Resp]` 제네릭 래퍼.
- `progress.go` — `WatchProgress`: `GET_PROGRESS`를 goroutine에서 polling → Go 채널 스트림.

의존성은 `golang.org/x/sys/windows`와 `github.com/vmihailenco/msgpack/v5`뿐이며,
`github.com/spf13/cobra`는 `sample/app` CLI 전용입니다.

## 설계 원칙

- **메커니즘/정책 분리**: I/O 라우팅·필터 스택·sweep·핸드오버 발행/읽기는 `lib`(메커니즘). 메타데이터
  복호화와 cipher 선택은 sample(정책) — 드라이버는 `VolumeProvider::on_attach`, 로더는 sample이 직접
  `BlockIoHookEngine`에 cipher를 넘김. `lib`은 full-volume 암호화 알고리즘을 하드코딩하지 않습니다.
- **언어 경계**: 커널/UEFI는 Rust+WDK, 관리 도구는 Go. 경계는 `DeviceIoControl` + msgpack.
- **두 I/O 경로**: `Encrypted`(고수준, sample이 만든 `VolumeCipher`를 키트가 sweep/데이터 경로에서 실행) /
  `Custom`(저수준, sample이 섹터 단위 직접 처리).
- **점진적 암호화 안전성**: `EncryptedOffsetStore`가 `encrypted_offset`을 영속화해 전원 차단 후 재개 가능.
  (남은 한계: 한 배치의 ciphertext 기록과 boundary 영속화 사이의 1배치 손상 창은 hotzone 저널링이 필요 —
  샘플 범위 밖, `offset/engine.rs`에 문서화.)
