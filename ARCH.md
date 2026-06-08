# volumecrypt-kit Architecture

## 개요

`volumecrypt-kit`은 Rust와 WDK(Windows Driver Kit)를 기반으로 하는 볼륨 암호화 라이브러리 키트입니다.
비동기 I/O를 통해 고성능을 달성하고, 명확한 인터페이스(Trait) 구현만으로 손쉽게 볼륨 암호화를 구성할 수 있도록 설계되었습니다.

Low-level 구현 (볼륨 포멧, 암호화 알고리즘 등 모든 부분들을 자체적으로 구현하고, volumecrypt-kit 에서는 volume filter 역할만 담당)과,
High-level 구현 (JvckMetadata 을 이용한 기본 구현) 이 가능합니다.

### OS Volume (시스템 볼륨)

- metadata가 볼륨 안에 저장되므로 UEFI 로더는 ACPI 핸드오버로 **VMK만** 드라이버에 전달합니다.
  (FVEK·encrypted_offset·지오메트리는 드라이버가 볼륨 footer metadata를 VMK로 복호화하여 복원합니다.)
- 드라이버는 부팅 시 핸드오버된 VMK가 있으면 EFI 접근 없이 볼륨 footer metadata만 읽어 자동으로 attach됩니다.
- OS Volume은 이미 파일시스템이 존재하는 기존 파티션이므로 볼륨 앞부분(header)에 metadata를 넣을 수 없습니다.
  최초 암호화 시 파일시스템을 Shrink하여 볼륨 끝부분에 **2개의 footer metadata replica**를 저장합니다 (`use_header=0`, `use_footer=2`).

샘플 구현 (JvckMetadata 사용):
- `(EFI)/vck.json` 에 평문 VMK 와 로더 설정을 저장합니다.
- JvckMetadata replica는 OS 볼륨 끝부분 footer 영역에 저장합니다. 로더는 부팅 시 이를 Block IO로 읽어
  VMK로 복호화한 뒤 FVEK와 encrypted_offset을 복원하고, `EFI_BLOCK_IO_PROTOCOL`을 후킹하여 OS 볼륨을
  **투명하게(transparent) 암·복호화**합니다. 드라이버에는 VMK만 ACPI 핸드오버로 전달합니다.

### Data Volume (데이터 볼륨)

- UEFI가 관여하지 않습니다.
- OS 부팅 후 Go 애플리케이션이 `IOCTL_JVCK_ATTACH`를 통해 볼륨 경로와 VMK 을 드라이버에 제공하여 암호화 레이어를 활성화합니다.
- **신규 파티션을 생성할 경우에만** 볼륨 앞부분(header)에 metadata를 넣을 수 있습니다 (`UseHeader=1`, `UseFooter=2`).
  기존 파티션은 이미 파일시스템이 모든 섹터를 점유하여 앞부분 섹터를 옮길 수 없으므로, Shrink로 끝부분에만
  Metadata 공간을 확보하고 header는 사용하지 않습니다 (`UseHeader=0`, `UseFooter=2`).
- 볼륨의 첫 4byte 을 보고 header Metadata 존재 유무를 파악합니다. footer는 `[vendor specific data][Metadata]`
  순서로 배치되어 Metadata 블록이 replica의 맨 끝(볼륨의 맨 끝)에 오므로, 볼륨 **마지막 섹터를 읽으면 즉시**
  footer Metadata signature를 발견할 수 있습니다.

---

## 저장소 구조

```
volumecrypt-kit/
├── lib/                         # Rust: 라이브러리 계층
│   ├── common/                  # 공통 타입, 에러, msgpack 핸드오버 헬퍼, JVCK 기본 metadata 포맷 (JvckMetadata) 에 대한 구현들
│   ├── driver/                  # 커널 드라이버 프레임워크 (WDK, 비동기 I/O, encrypted_offset)
│   └── loader/                  # UEFI 로더 프레임워크 (Block IO 후킹, ACPI 핸드오버)
│
├── sdk/                         # Go: 유저스페이스 SDK
│   └── vck/                     # 드라이버 IOCTL 클라이언트 라이브러리
│
├── sample/                      # JVCK 기본 metadata 포맷 (JvckMetadata) 만을 사용하는 예제
│   ├── common/                  # Rust: vck.json(VMK/loader 설정) 파싱, JVCK 메타데이터, 핸드오버 페이로드 정의
│   ├── crypto-test/             # Rust: 암호화 프리미티브(JVCK/AES-XTS/HKDF) 검증용 테스트 크레이트
│   ├── driver/                  # Rust: VolumeProvider 구현체 (AES-XTS)
│   ├── loader/                  # Rust: UEFI 로더 구현체
│   └── app/                     # Go: 관리용 CLI (OS/Data 볼륨 attach·암호화·복호화·상태 조회)
│
├── testing/                     # VM 기반 테스트 자산 (test-foundry, OVMF, recipes 등) — 자세한 내용은 AGENTS.md 참조
├── Cargo.toml                   # Rust workspace
├── go.mod                       # Go module root (github.com/jc-lab/volumecrypt-kit)
├── go.sum
└── ARCH.md
```

### 언어별 모듈 경계

| 언어 | 범위 | 빌드 단위 |
|---|---|---|
| Rust | `lib/`, `sample/common`, `sample/crypto-test`, `sample/driver`, `sample/loader` | Cargo workspace |
| Go | `sdk/`, `sample/app` | Go module (`go.mod`) |

`go.mod` 루트 모듈 이름은 `github.com/jc-lab/volumecrypt-kit`이며,
`sdk` 패키지는 `github.com/jc-lab/volumecrypt-kit/sdk`로 임포트됩니다.

---

## 컴포넌트 상세

### lib/common

드라이버, 로더, 애플리케이션 전반에서 공유되는 기반 코드입니다.

**주요 역할:**

- 공통 에러 타입 (`VckError`, `VckResult<T>`)
- 볼륨 메타데이터 타입 (`VolumeId`, `SectorRange`, `EncryptedOffset`)
- UEFI→Driver 핸드오버 추상화
  - `HandoverPayload` 트레이트: `messagepack-serde`(no_std)를 통한 직렬화/역직렬화 인터페이스
  - `AcpiHandoverWriter` (로더 측): `EfiRuntimeServicesData`로 msgpack 버퍼를 할당하고 커스텀 ACPI 테이블에 물리 주소를 기록
  - `AcpiHandoverReader` (드라이버 측): ACPI 테이블에서 물리 주소를 읽어 msgpack 버퍼를 역직렬화
- 공통 상수 및 유틸리티

```
lib/common/
├── src/
│   ├── lib.rs
│   ├── error.rs           # VckError, VckResult
│   ├── types.rs           # EncryptedOffset, SectorRange, VolumeId, Guid
│   ├── store.rs           # SectorIo, EncryptedOffsetStore 트레이트
│   ├── jvck/
│   │   ├── mod.rs
│   │   ├── metadata.rs    # JvckMetadata/EncryptedMetadata, 키 파생, CRC/HMAC
│   │   ├── options.rs     # JvckMetadataOptions
│   │   └── store.rs       # JvckMetadataStore<S: SectorIo> (+ uefi UefiBlockIoVolume)
│   └── handover/
│       ├── mod.rs
│       ├── payload.rs     # HandoverPayload trait
│       ├── writer.rs      # AcpiHandoverWriter (UEFI 측)
│       └── reader.rs      # AcpiHandoverReader (Driver 측)
└── Cargo.toml
```

> `EncryptedOffsetStore`/`SectorIo` 트레이트는 의존성 그래프상 `lib/common`(`store.rs`)에 두고
> `lib/driver`가 재노출합니다. `JvckMetadataStore`는 `SectorIo`에 대해 generic이며, 커널은
> `lib/driver`의 `KernelVolumeIo`, UEFI는 `lib/common`의 `UefiBlockIoVolume`(uefi feature)를 사용합니다.

**핵심 타입:**

```rust
/// 점진적 암호화 진행 상태.
///
/// 모든 섹터 번호는 **데이터 영역(offset_sector) 기준 상대값**입니다.
/// 즉 0 = 암호화 대상 영역의 첫 섹터이며, header/footer metadata 영역은 포함하지 않습니다.
/// 필터 드라이버는 절대 LBA를 `relative = lba - offset_sector`로 환산하여 이 값과 비교합니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedOffset {
    /// 이 섹터 이전까지는 암호화 완료 (데이터 영역 상대 섹터 번호)
    pub sector: u64,
    /// 암호화 대상 총 섹터 수 (metadata 영역 제외, 데이터 영역 크기와 동일)
    pub total_sectors: u64,
}

impl EncryptedOffset {
    /// `sector`는 데이터 영역 상대 섹터 번호입니다.
    pub fn is_encrypted(&self, sector: u64) -> bool {
        sector < self.sector
    }
    pub fn is_fully_encrypted(&self) -> bool {
        self.sector >= self.total_sectors
    }
}

/// UEFI → Driver 핸드오버 페이로드 트레이트
pub trait HandoverPayload: Serialize + DeserializeOwned {
    /// ACPI 테이블 서명 (4바이트, sample에서 지정)
    const ACPI_SIGNATURE: [u8; 4];
    /// ACPI OEM ID (6바이트, sample에서 지정)
    const ACPI_OEM_ID: [u8; 6];
}
```

---

### lib/driver

Windows 커널 드라이버 계층의 핵심 로직입니다. WDK crate를 기반으로 하며,
I/O 완료 콜백 기반의 비동기 실행기를 내장합니다.

**주요 역할:**

- `VolumeProvider` 트레이트 정의 (Attach/Detach/IO 훅)
- 볼륨 필터 드라이버 스택 관리 (`VolumeFilterDriver`)
- 섹터 레벨 비동기 Read/Write 파이프라인
- `EncryptedOffset` 기반 점진적 암호화 상태 머신
- AES-XTS 고수준 경로: 키 등록만으로 내부에서 자동 암·복호화
- 저수준 경로: 사용자 정의 Read/Write 훅 호출

```
lib/driver/
├── src/
│   ├── lib.rs
│   ├── executor.rs         # 커널 비동기 실행기 (IoCompletion 기반)
│   ├── filter/
│   │   ├── mod.rs
│   │   ├── manager.rs      # VolumeFilterDriver: 드라이버 스택 attach/detach
│   │   ├── irp.rs          # IRP Read/Write 인터셉트 및 비동기 디스패치
│   │   └── context.rs      # 볼륨별 필터 컨텍스트
│   ├── provider.rs         # VolumeProvider trait + AttachContext/DetachContext
│   ├── registry.rs         # VolumeAttachRegistry: 현재 attach된 볼륨 목록 관리
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── pipeline.rs     # 비동기 암·복호화 파이프라인
│   │   └── aes_xts.rs      # AES-XTS 커널 구현 래퍼
│   ├── offset/
│   │   ├── mod.rs
│   │   └── engine.rs       # 점진적 암호화 상태 머신
│   ├── ioctl/
│   │   ├── mod.rs
│   │   ├── codes.rs        # IOCTL 코드 상수 (Go SDK와 공유되는 값)
│   │   ├── types.rs        # IOCTL 요청/응답 msgpack 구조체
│   │   └── dispatch.rs     # IRP_MJ_DEVICE_CONTROL 핸들러
│   ├── io.rs               # KernelVolumeIo: 하위 볼륨 디바이스 raw 섹터 SectorIo 구현
│   ├── device.rs           # 컨트롤 디바이스 객체 생성 및 심볼릭 링크 관리
│   └── handover.rs         # AcpiHandoverReader 래퍼
└── Cargo.toml
```

**컨트롤 디바이스 객체:**

드라이버는 로드 시 다음 두 가지 NT 오브젝트를 생성합니다.

```
\Device\VolumeCryptKitSample          ← 커널 내부 디바이스 이름
\DosDevices\VolumeCryptKitSample      ← 유저스페이스 심볼릭 링크 (\\.\VolumeCryptKitSample)
```

Go SDK는 `CreateFile("\\.\VolumeCryptKitSample", ...)` 으로 핸들을 열고
`DeviceIoControl`로 IOCTL을 전송합니다.

**IOCTL 코드 (codes.rs):**

```rust
// CTL_CODE(DeviceType=0x22, Function, Method=METHOD_BUFFERED, Access=FILE_ANY_ACCESS)
// = (0x22 << 16) | (Function << 2)
pub const IOCTL_VCK_GET_STATUS:    u32 = 0x0022_2000; // Function = 0x800 (공통)
pub const IOCTL_VCK_START_ENCRYPT: u32 = 0x0022_2004; // Function = 0x801 (공통)
pub const IOCTL_VCK_START_DECRYPT: u32 = 0x0022_2008; // Function = 0x802 (공통)
pub const IOCTL_VCK_GET_PROGRESS:  u32 = 0x0022_200c; // Function = 0x803 (공통)
pub const IOCTL_VCK_PAUSE:         u32 = 0x0022_2010; // Function = 0x804 (공통)
pub const IOCTL_JVCK_ATTACH:       u32 = 0x0022_2014; // Function = 0x805 (JVCK 포맷 전용, Data Volume)
pub const IOCTL_VCK_DETACH:        u32 = 0x0022_2018; // Function = 0x806 (공통, Data Volume)
```

`IOCTL_JVCK_ATTACH`는 JVCK 기본 포맷 전용 attach IOCTL입니다. 나머지 IOCTL(GET_STATUS,
START_ENCRYPT, START_DECRYPT, GET_PROGRESS, PAUSE, DETACH)은 attach된 볼륨을 `volume_path`로
지정해 동작하므로 포맷과 무관하게 공통으로 사용합니다. 자체 포맷을 쓰는 사용자는 attach만
별도 IOCTL로 구현하고 나머지 공통 IOCTL은 그대로 재사용할 수 있습니다.

**IOCTL 입출력 포맷:** 입력 버퍼와 출력 버퍼 모두 msgpack을 사용합니다 (Rust: `messagepack-serde`,
Go: `github.com/vmihailenco/msgpack/v5`). Go SDK와 Rust 드라이버 사이의 구조체 정의는 아래 sdk 섹션에서 설명합니다.

`IOCTL_VCK_GET_PROGRESS`는 **논블로킹 IOCTL**입니다. 드라이버는 현재 진행률 스냅샷을 즉시 반환합니다.
Go SDK는 이를 goroutine에서 주기적으로 polling하여 채널 스트림으로 변환합니다.

IOCTL 디스패치는 요청을 처리하기 전에 `IoctlAuthorization::authorize()`를 호출합니다.
기본 정책은 sample에서 구현하며, 예시는 `IOCTL_VCK_GET_PROGRESS`만 일반 사용자에게 허용하고
나머지 IOCTL은 관리자 권한을 요구합니다.

**두 가지 볼륨 Attach 경로:**

```
┌─────────────────────────────────────────────────────────────────┐
│                        OS Volume (System)                       │
│                                                                 │
│  [DriverEntry]                                                  │
│    AcpiHandoverReader → VckHandoverPayload (partition_guid, vmk) │
│      → VMK를 보호 메모리로 복사 후 ACPI 버퍼 zeroize             │
│         │                                                       │
│  [PnP 볼륨 도착 알림]                                           │
│    VolumeProvider::on_attach(AttachContext { handover_data })   │
│      → VMK로 볼륨 footer metadata 복호화                        │
│        → FVEK·encrypted_offset·지오메트리 복원                  │
│        → IoConfig::AesXts 반환                                  │
│         → VolumeAttachRegistry에 등록                           │
│         → 필터 드라이버 스택에 삽입                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       Data Volume (일반, JVCK)                   │
│                                                                 │
│  [IOCTL_JVCK_ATTACH 수신]                                       │
│    JvckVolumeAttachReq { volume_path, vmk,                      │
│                          use_header, use_footer, metadata_size }│
│         │                                                       │
│    lib/driver: 볼륨에서 JVCK metadata(header/footer) 탐색·검증   │
│      - 존재하면 VMK로 복호화 → FVEK·encrypted_offset 복원        │
│      - 없으면(최초) 새 metadata 생성 후 기록                     │
│         → VolumeAttachRegistry에 등록                           │
│         → 필터 드라이버 스택에 삽입                              │
│         ← JvckVolumeAttachResp { offset_sector, total_sectors,  │
│                                  sector_size }                  │
└─────────────────────────────────────────────────────────────────┘

두 경로 모두 VolumeAttachRegistry에 등록된 후에는
GET_STATUS / START_ENCRYPT / START_DECRYPT / GET_PROGRESS / PAUSE
IOCTL을 동일하게 사용합니다.
```

**VolumeAttachRegistry (registry.rs):**

```rust
/// 현재 드라이버에 attach된 모든 볼륨을 추적합니다.
/// OS Volume(부팅 시 자동 등록)과 Data Volume(IOCTL 등록) 모두 보관합니다.
pub struct VolumeAttachRegistry {
    // volume_path (NT Device Path) → AttachedVolume
    entries: Mutex<BTreeMap<String, Arc<AttachedVolume>>>,
}

pub struct AttachedVolume {
    pub volume_path:   String,
    pub io_config:     IoConfig,
    pub encryption:    Mutex<EncryptionEngine>,
    pub offset_store:  Arc<dyn EncryptedOffsetStore>,
    pub attach_source: AttachSource,
}

pub enum AttachSource {
    /// OS Volume: ACPI 핸드오버로 자동 attach
    Handover,
    /// Data Volume: IOCTL_JVCK_ATTACH로 런타임 attach
    Ioctl,
}
```

**VolumeProvider 트레이트 (핵심 인터페이스):**

```rust
/// OS Volume의 부팅 시 attach 콜백. Data Volume은 사용하지 않습니다.
///
/// `Payload`는 연관 타입으로, 사용자가 자체 핸드오버 포맷을 정의할 수 있게 합니다.
/// lib/driver는 이 타입으로 ACPI 핸드오버 버퍼를 직접 역직렬화하여 `AttachContext`에
/// 구체 타입으로 전달하므로, sample에서 `dyn Any` downcast가 필요 없습니다.
pub trait VolumeProvider: Send + Sync + 'static {
    /// 핸드오버 페이로드 타입 (LoaderProvider::Payload와 동일 타입을 사용).
    type Payload: HandoverPayload;

    /// 볼륨 attach 시 호출 (OS Volume 전용).
    /// IoConfig를 반환하여 암호화 방식을 결정합니다.
    async fn on_attach(&self, ctx: &AttachContext<'_, Self::Payload>) -> VckResult<IoConfig>;

    /// 볼륨 detach 시 호출 (OS Volume 전용).
    async fn on_detach(&self, ctx: &DetachContext<'_>) -> VckResult<()>;
}

/// Attach 시 반환하는 I/O 동작 설정.
/// `offset_sector`는 데이터(암호화 대상) 영역 시작 절대 LBA이며, lib은 이를 기준으로
/// `rel = lba - offset_sector`를 계산하고 metadata 영역 I/O는 passthrough합니다.
pub enum IoConfig {
    /// 이 볼륨에는 필터를 attach하지 않고 그대로 통과
    Passthrough,

    /// 고수준: lib/driver 내부에서 AES-XTS로 자동 처리
    AesXts {
        key1: [u8; 32],
        key2: [u8; 32],
        offset_sector: u64,
        encrypted_offset: EncryptedOffset,
        offset_store: Arc<dyn EncryptedOffsetStore>,
    },

    /// 저수준: sample이 직접 Read/Write 훅 구현
    Custom {
        io_hooks: Arc<dyn IoHooks>,
        offset_sector: u64,
        encrypted_offset: EncryptedOffset,
        offset_store: Arc<dyn EncryptedOffsetStore>,
    },
}

/// 저수준 I/O 훅 인터페이스. `sector`는 데이터 영역(offset_sector) 기준 상대 섹터 번호입니다.
pub trait IoHooks: Send + Sync + 'static {
    async fn read(&self, sector: u64, buf: &mut [u8]) -> VckResult<()>;
    async fn write(&self, sector: u64, buf: &[u8]) -> VckResult<()>;
}

/// 볼륨 식별자. 필터가 attach 대상을 식별하고 raw 섹터에 접근하는 데 사용합니다.
pub struct VolumeId {
    /// GPT 파티션 고유 GUID (핸드오버 partition_guid와 매칭)
    pub partition_guid: Guid,
    /// NT 디바이스 경로 (예: \Device\HarddiskVolume3). raw footer metadata 읽기/쓰기에 사용.
    pub device_path: String,
}

pub struct AttachContext<'a, P: HandoverPayload> {
    pub volume_id:      &'a VolumeId,
    pub sector_size:    u32,
    /// 볼륨(파티션) 전체 섹터 수 (raw capacity). 데이터 영역/footer 위치는 provider가
    /// metadata를 읽어 계산하므로, lib은 raw 용량만 제공합니다.
    pub volume_sectors: u64,
    /// 핸드오버에서 읽어와 P로 역직렬화된 드라이버 전달 데이터
    pub handover_data:  Option<&'a P>,
}

/// encrypted_offset의 지속 저장을 담당합니다.
/// Data Volume은 이 트레이트 구현을 반드시 사용해야 하며,
/// OS Volume도 기본 JVCK 구현을 통해 같은 경로로 저장할 수 있습니다.
pub trait EncryptedOffsetStore: Send + Sync + 'static {
    fn load(&self) -> VckResult<EncryptedOffset>;
    fn store(&self, offset: &EncryptedOffset) -> VckResult<()>;
    fn flush(&self) -> VckResult<()>;
}

/// IOCTL 권한 검사를 sample이 손쉽게 구현할 수 있게 하는 훅입니다.
pub trait IoctlAuthorization: Send + Sync + 'static {
    fn authorize(&self, ctx: &IoctlAuthContext<'_>) -> VckResult<()>;
}

pub struct IoctlAuthContext<'a> {
    pub ioctl_code: u32,
    pub requestor_mode: RequestorMode,
    pub requestor_token: Option<&'a AccessToken>,
}

// dispatch.rs 개념 흐름
fn dispatch_ioctl(ctx: &IoctlAuthContext<'_>) -> VckResult<IoctlResponse> {
    provider.authorize(ctx)?;
    match ctx.ioctl_code {
        IOCTL_VCK_GET_STATUS => handle_get_status(ctx),
        IOCTL_VCK_START_ENCRYPT => handle_start_encrypt(ctx),
        IOCTL_VCK_START_DECRYPT => handle_start_decrypt(ctx),
        IOCTL_VCK_GET_PROGRESS => handle_get_progress(ctx),
        IOCTL_VCK_PAUSE => handle_pause(ctx),
        IOCTL_JVCK_ATTACH => handle_jvck_attach(ctx),
        IOCTL_VCK_DETACH => handle_detach(ctx),
        _ => Err(VckError::InvalidIoctl),
    }
}
```

**비동기 실행기 (커널 공간):**

Windows 커널은 표준 Rust async runtime을 사용할 수 없습니다.
`lib/driver`는 `IoCompletion` 콜백과 커널 스레드풀(`ExWorkItem`)을 기반으로
최소한의 `Future` 폴링 실행기를 제공합니다.

```rust
// 내부 실행기: IRP completion 콜백에서 waker를 호출하여 폴링
pub struct KernelExecutor { /* ... */ }

impl KernelExecutor {
    pub fn spawn<F: Future<Output = ()> + Send + 'static>(&self, fut: F);
    pub fn block_on<F: Future>(&self, fut: F) -> F::Output;
}
```

**encrypted_offset 상태 머신:**

모든 비교는 데이터 영역 상대 섹터(`rel = lba - offset_sector`) 기준입니다.
header/footer metadata 영역(데이터 영역 밖)에 대한 I/O는 암·복호화 없이 그대로 통과시킵니다.

```
[볼륨 Attach]
     │
     ▼
EncryptionEngine::new(encrypted_offset, total_sectors)
     │
     ├─ Read(lba) ─────────────────────────────────────────────────────────┐
     │   lba가 metadata 영역      →  passthrough (평문 그대로)             │
     │   rel = lba - offset_sector                                         │
     │   rel < encrypted_offset   →  AES-XTS 복호화 후 반환                │
     │   rel >= encrypted_offset  →  평문 그대로 반환                      │
     │                                                                     │
     ├─ Write(lba) ────────────────────────────────────────────────────────┤
     │   lba가 metadata 영역      →  passthrough (평문 그대로)             │
     │   rel = lba - offset_sector                                         │
     │   rel < encrypted_offset   →  AES-XTS 암호화 후 하위 드라이버로     │
     │   rel >= encrypted_offset  →  평문 그대로 하위 드라이버로           │
     │                                                                     │
     └─ ProgressEncryption() ──────────────────────────────────────────────┘
         배치 단위로 encrypted_offset 이후 섹터를 읽어
         AES-XTS 암호화 후 기록, offset_store.store()/flush()로 encrypted_offset 영속화
```

**JvckMetadata(JVCK 기본 메타데이터) 포맷 (lib 제공):**

lib은 Data Volume과 OS Volume 모두에서 사용할 수 있는 기본 메타데이터 포맷을 제공합니다.
사용자는 이 포맷을 그대로 쓰거나 `EncryptedOffsetStore`와 attach 로직을 직접 구현하여
자기만의 포맷을 사용할 수 있습니다. 기본 JVCK 포맷을 사용할 경우 VMK 입력이 필요합니다.
OS Volume과 Data Volume 모두 **볼륨 자체의 header/footer 영역**에 replica를 저장합니다 (EFI 파일을
사용하지 않습니다). OS Volume은 기존 파일시스템이 존재하므로 header를 쓸 수 없고, 최초 암호화 시
파일시스템을 Shrink하여 끝부분에 2개의 footer replica를 둡니다 (`use_header = 0`, `use_footer = 2`).

드라이버에서 지정 가능한 기본 포맷 옵션은 다음과 같습니다.

```rust
pub struct JvckMetadataOptions {
    /// 볼륨 header 영역에 중복 저장할 metadata replica 개수 (신규 파티션만 가능)
    pub use_header: u32,
    /// 볼륨 footer 영역에 중복 저장할 metadata replica 개수
    pub use_footer: u32,
    /// replica 하나의 영역 크기(벤더 데이터 포함). 최소 128KiB.
    pub metadata_size: u32,
}
```

`metadata_size`는 replica 한 개가 차지하는 영역 전체 크기이며 최소 128KiB입니다.
`use_header + use_footer >= 1`이어야 합니다. Header replica는 볼륨 시작부터 순서대로 배치하고,
Footer replica는 볼륨 끝에서 역순으로 배치합니다. 암호화 대상 데이터 영역(=`total_sectors`)은
header/footer replica 영역을 제외한 부분이며, 시작 절대 LBA는
`offset_sector = use_header * metadata_size / sector_size` 입니다.

**replica 내부 배치** — replica 한 개는 고정 512바이트 **Metadata 블록**과 나머지 **Vendor specific data**로
구성됩니다. metadata를 찾는 과정을 단순화하기 위해 Vendor data는 Metadata와 분리하여 배치합니다.

- Header replica: `[Metadata(512B)][Vendor specific data]` — Metadata가 replica의 맨 앞.
- Footer replica: `[Vendor specific data][Metadata(512B)]` — Metadata가 replica의 맨 끝.

이렇게 하면 footer의 마지막 replica Metadata가 볼륨의 맨 끝 512바이트에 위치하므로, 끝에서부터
역순으로 스캔할 때 마지막 섹터에서 곧바로 `JVCK` signature를 만날 수 있습니다.

Metadata 블록(512바이트) 구조는 다음과 같습니다. 모든 숫자는 little endian이며, 모든 용량 단위는 bytes입니다. `Header CRC32`는 offset 0부터 507까지의 영역에 대해 계산합니다.

| Offset | Size | Description |
| ------ | ---- | ----------- |
| 0      | 4    | signature `JVCK` |
| 4      | 8    | Vendor ID |
| 12     | 2    | VCK Metadata Version |
| 14     | 2    | Vendor Specific Version |
| 16     | 4    | Metadata Size (이 replica 영역 전체 크기, 벤더 데이터 포함) |
| 20     | 4    | Sector Size (e.g. 512) |
| 24     | 1    | Header replica count |
| 25     | 1    | Footer replica count |
| 26     | 6    | Reserved (zero) |
| 32     | 16   | Volume ID (UUIDv4) |
| 48     | 128  | Encrypted Metadata |
| 176    | 32   | HMAC-SHA256(key = EncryptedMetadata_MAC_KEY, data = 암호화된 EncryptedMetadata) |
| 208    | 300  | Reserved (zero) |
| 508    | 4    | Header CRC32 |

Vendor specific data는 Metadata 블록 **밖**에 위치하며(위 replica 내부 배치 참조), 크기는
`metadata_size - 512`입니다.

**EncryptedMetadata**는 AES-256-CBC(no padding)로 암호화하며,
`EncryptedMetadata_ENC_KEY`, `EncryptedMetadata_ENC_IV`를 사용합니다. 고정 크기는 128바이트입니다.

| Offset | Size | Description |
| ------ | ---- | ----------- |
| 0      | 4    | signature `JVCK` |
| 4      | 12   | must zero (복호화 후 0이 아니면 VMK 불일치/손상으로 판정하는 무결성 검증 패턴) |
| 16     | 8    | encrypted_offset |
| 24     | 8    | reserved (zero) |
| 32     | 32   | FVEK Key1 (encryption key) |
| 64     | 32   | FVEK Key2 (tweak key) |
| 96     | 32   | reserved (zero) |

키 파생은 다음과 같습니다.

```text
EncryptedMetadata_MAC_KEY = HKDF_SHA256(salt = Volume ID, ikm = VMK, info = "EncryptedMetadata:MAC", length = 32)
EncryptedMetadata_ENC_KEY = HKDF_SHA256(salt = Volume ID, ikm = VMK, info = "EncryptedMetadata:ENC", length = 32)
EncryptedMetadata_ENC_IV  = HKDF_SHA256(salt = Volume ID, ikm = VMK, info = "EncryptedMetadata:IV",  length = 16)
```

`JvckMetadataStore`는 `EncryptedOffsetStore`를 구현하며, OS/Data Volume 모두 볼륨의 header/footer
replica를 대상으로 동작합니다. `store()`는 모든 configured replica에 동일한 encrypted_offset을
기록하고, `load()`는 HMAC 검증에 성공한 replica만 후보로 사용합니다.

**복구 정책:** replica 간 `encrypted_offset` 값이 다르면(암호화 진행 중 강제 종료 등) **가장 큰
값을 채택**합니다. 진행 방향상 더 큰 offset까지는 이미 암호화가 적용되었을 수 있으므로, 큰 값을
택해야 평문을 암호문으로 오인하는 일이 없습니다. 불일치 발견 시 운영 로그에 replica mismatch를
남기고, 채택한 값으로 모든 replica를 재동기화합니다.

---

### lib/loader

UEFI 환경에서 동작하는 로더 프레임워크입니다. `uefi` crate 기반입니다.

**주요 역할:**

- `LoaderProvider` 트레이트 정의 (로더가 sample에게 요구하는 인터페이스)
- `EFI_BLOCK_IO_PROTOCOL` 및 `EFI_BLOCK_IO2_PROTOCOL` 후킹 엔진
- UEFI→Driver 핸드오버 데이터 기록 (`AcpiHandoverWriter` 래퍼)
- 다음 OS 로더 체인로드 유틸리티

```
lib/loader/
├── src/
│   ├── lib.rs
│   ├── provider.rs          # LoaderProvider trait
│   ├── hook/
│   │   ├── mod.rs
│   │   ├── block_io.rs      # EFI_BLOCK_IO_PROTOCOL 후킹
│   │   └── block_io2.rs     # EFI_BLOCK_IO2_PROTOCOL 후킹
│   ├── handover.rs          # AcpiHandoverWriter 래퍼 (lib/common 사용)
│   └── chainload.rs         # 다음 EFI 바이너리 체인로드
└── Cargo.toml
```

**LoaderProvider 트레이트:**

```rust
pub trait LoaderProvider: 'static {
    type Payload: HandoverPayload;

    /// 로더 초기화 시 호출. 암호화 설정 및 핸드오버 페이로드 반환
    fn on_init(&self, boot_services: &BootServices) -> VckResult<LoaderConfig<Self::Payload>>;

    /// Block IO Read 훅 (고수준 선택 시 lib가 AES-XTS 자동 처리)
    fn read_hook(&self, lba: u64, buf: &mut [u8]) -> VckResult<()> {
        // 기본 구현: 훅 없음 (고수준 경로에서는 lib이 처리)
        Ok(())
    }
}

pub struct LoaderConfig<P: HandoverPayload> {
    /// 드라이버로 전달할 핸드오버 데이터
    pub handover_payload: P,
    /// 체인로드할 다음 EFI 바이너리 경로
    pub next_loader: DevicePath,
    /// AES-XTS 키 (고수준 경로, None이면 read_hook 사용)
    pub crypto: Option<LoaderCrypto>,
}

pub struct LoaderCrypto {
    pub key1: [u8; 32],
    pub key2: [u8; 32],
    /// 데이터(암호화 대상) 영역 시작 절대 LBA. 후킹된 Read에서 rel = lba - offset_sector 계산에 사용.
    pub offset_sector: u64,
    pub encrypted_offset: EncryptedOffset,
}
```

**Block IO 후킹 메커니즘:**

```
[UEFI Boot Services]
        │
        ▼
  lib/loader 초기화
        │
        ├─ LocateHandleBuffer(EFI_BLOCK_IO_PROTOCOL)
        │       모든 Block IO 디바이스 열거
        │
        ├─ 대상 파티션 GUID 매칭
        │
        └─ 원본 Read 함수 포인터 저장
           vtable의 ReadBlocks / ReadBlocksEx 교체
                │
                ▼
         후킹된 ReadBlocks(lba, buf)
                │
                ├─ lba가 metadata 영역          →  원본 Read 그대로 반환 (passthrough)
                │  rel = lba - offset_sector
                ├─ rel < encrypted_offset       →  원본 Read 후 AES-XTS 복호화
                └─ rel >= encrypted_offset      →  원본 Read 그대로 반환
```

---

## Go SDK (sdk)

`sdk` 패키지는 Go 유저스페이스 애플리케이션이 커널 드라이버와 통신하기 위한
클라이언트 라이브러리입니다. `DeviceIoControl` Win32 API를 래핑하여
타입 안전한 Go 인터페이스를 제공합니다.

```
sdk/
├── client.go          # Client 구조체: Open/Close, IOCTL 디스패치
├── types.go           # 공유 타입: VolumeStatus, EncryptRequest, ProgressEvent, ...
├── ioctl.go           # IOCTL 코드 상수 및 DeviceIoControl 래퍼 (Windows)
└── progress.go        # WatchProgress: non-blocking progress polling → Go channel 변환
```

**go.mod:**

```
module github.com/jc-lab/volumecrypt-kit

go 1.22

require (
    github.com/spf13/cobra v1.8.1            // sample/app(CLI) 전용
    github.com/vmihailenco/msgpack/v5 v5.4.1 // IOCTL msgpack
    golang.org/x/sys v0.24.0                 // Win32 API
)
```

`sdk` 패키지 자체는 `golang.org/x/sys/windows`와 `github.com/vmihailenco/msgpack/v5`만 사용합니다.
`github.com/spf13/cobra`는 `sample/app`(CLI)에서만 사용합니다.

### 타입 (types.go)

```go
package vck

// EncryptionState는 드라이버가 보고하는 볼륨의 암호화 진행 상태입니다.
type EncryptionState int

const (
    StateIdle       EncryptionState = 0 // 대기 중 (전체 암호화 완료 포함)
    StateEncrypting EncryptionState = 1 // 점진적 암호화 진행 중
    StateDecrypting EncryptionState = 2 // 점진적 복호화 진행 중
    StatePaused     EncryptionState = 3 // 일시 중지
)

// VolumeStatus는 IOCTL_VCK_GET_STATUS 응답 구조체입니다.
type VolumeStatus struct {
    VolumePath      string          `msgpack:"volume_path"`
    State           EncryptionState `msgpack:"state"`
    EncryptedSector uint64          `msgpack:"encrypted_sector"`
    TotalSectors    uint64          `msgpack:"total_sectors"`
    SectorSize      uint32          `msgpack:"sector_size"`
    IsAttached      bool            `msgpack:"is_attached"`
}

func (s *VolumeStatus) ProgressPercent() float64 {
    if s.TotalSectors == 0 {
        return 0
    }
    return float64(s.EncryptedSector) / float64(s.TotalSectors) * 100
}

func (s *VolumeStatus) IsFullyEncrypted() bool {
    return s.EncryptedSector >= s.TotalSectors
}

// ─── Data Volume: Attach / Detach ────────────────────────────────────────────

// JvckVolumeAttachRequest는 IOCTL_JVCK_ATTACH 요청 구조체입니다.
// JVCK 기본 포맷으로 Data Volume을 드라이버에 등록하고 암호화 레이어를 활성화합니다.
// offset_sector/total_sectors/encrypted_sector 등은 JVCK metadata에서 복원되거나
// (use_header/use_footer/metadata_size로) 계산되므로 요청에 포함하지 않습니다.
type JvckVolumeAttachRequest struct {
    // Required. 볼륨 경로. volume GUID 경로(\\?\Volume{...}\) 또는 드라이브 경로(C:\, \\.\D:) 모두 허용.
    VolumePath   string `msgpack:"volume_path"`
    // Required. JVCK metadata를 열기 위한 VMK.
    VMK          []byte `msgpack:"vmk"`
    // Required. header replica 개수. 신규 파티션만 1 이상 가능, 기존 파티션은 0.
    UseHeader    uint32 `msgpack:"use_header"`
    // Required. footer replica 개수. use_header + use_footer >= 1 이어야 함.
    UseFooter    uint32 `msgpack:"use_footer"`
    // Required. replica 한 개 영역 크기(벤더 데이터 포함). 최소 128KiB.
    MetadataSize uint32 `msgpack:"metadata_size"`
}

// JvckVolumeAttachResponse는 IOCTL_JVCK_ATTACH 응답 구조체입니다.
type JvckVolumeAttachResponse struct {
    OffsetSector uint64 `msgpack:"offset_sector"`
    TotalSectors uint64 `msgpack:"total_sectors"` // 실제 암호화 대상 영역 섹터 수
    SectorSize   uint32 `msgpack:"sector_size"`
}

// VolumeDetachRequest는 IOCTL_VCK_DETACH 요청 구조체입니다.
// attach된 Data Volume의 암호화 레이어를 해제합니다.
type VolumeDetachRequest struct {
    VolumePath string `msgpack:"volume_path"`
}

// ─── 암호화 진행 제어 ─────────────────────────────────────────────────────────

// volumeRequest는 volume_path만 전달하는 공통 요청 구조체입니다.
// GetStatus / Pause / GetProgress IOCTL에서 사용합니다. (StartEncrypt/StartDecrypt는
// 의미를 명확히 하기 위해 동일 형태의 EncryptRequest/DecryptRequest를 별도로 둡니다.)
type volumeRequest struct {
    VolumePath string `msgpack:"volume_path"`
}

// EncryptRequest는 IOCTL_VCK_START_ENCRYPT 요청 구조체입니다.
// 키는 Attach 시 이미 설정되므로 포함하지 않습니다.
// OS Volume과 Data Volume 모두 동일하게 사용합니다.
type EncryptRequest struct {
    VolumePath string `msgpack:"volume_path"`
}

// DecryptRequest는 IOCTL_VCK_START_DECRYPT 요청 구조체입니다.
type DecryptRequest struct {
    VolumePath string `msgpack:"volume_path"`
}

// ProgressEvent는 IOCTL_VCK_GET_PROGRESS 응답으로 수신하는 현재 진행률입니다.
type ProgressEvent struct {
    EncryptedSector uint64          `msgpack:"encrypted_sector"`
    TotalSectors    uint64          `msgpack:"total_sectors"`
    State           EncryptionState `msgpack:"state"`
    ErrorMessage    string          `msgpack:"error,omitempty"`
}

func (e *ProgressEvent) ProgressPercent() float64 {
    if e.TotalSectors == 0 {
        return 0
    }
    return float64(e.EncryptedSector) / float64(e.TotalSectors) * 100
}
```

### IOCTL 코드 (ioctl.go)

```go
package vck

import (
    "unsafe"

    "github.com/vmihailenco/msgpack/v5"
    "golang.org/x/sys/windows"
)

// lib/driver/src/ioctl/codes.rs 와 동일한 값
const (
    ioctlGetStatus    = 0x0022_2000
    ioctlStartEncrypt = 0x0022_2004
    ioctlStartDecrypt = 0x0022_2008
    ioctlGetProgress  = 0x0022_200c
    ioctlPause        = 0x0022_2010
    ioctlJvckAttach   = 0x0022_2014 // JVCK 포맷 Data Volume: 암호화 레이어 활성화
    ioctlDetach       = 0x0022_2018 // Data Volume: 암호화 레이어 해제
)

// deviceControl은 DeviceIoControl을 msgpack 직렬화로 래핑합니다.
func deviceControl[Req any, Resp any](
    handle windows.Handle,
    code   uint32,
    req    *Req,
) (*Resp, error) {
    inBuf, err := msgpack.Marshal(req)
    if err != nil {
        return nil, err
    }
    outBuf := make([]byte, 65536)
    var bytesReturned uint32

    err = windows.DeviceIoControl(
        handle, code,
        &inBuf[0], uint32(len(inBuf)),
        &outBuf[0], uint32(len(outBuf)),
        &bytesReturned, nil,
    )
    if err != nil {
        return nil, err
    }
    var resp Resp
    if err := msgpack.Unmarshal(outBuf[:bytesReturned], &resp); err != nil {
        return nil, err
    }
    return &resp, nil
}
```

### 클라이언트 API (client.go)

```go
package vck

const devicePath = `\\.\VolumeCryptKitSample`

// Client는 VolumeCryptKitSample 커널 드라이버와의 연결을 나타냅니다.
type Client struct {
    handle windows.Handle
}

// Open은 드라이버 디바이스를 열고 Client를 반환합니다.
func Open() (*Client, error) {
    h, err := windows.CreateFile(
        windows.StringToUTF16Ptr(devicePath),
        windows.GENERIC_READ|windows.GENERIC_WRITE,
        0, nil,
        windows.OPEN_EXISTING,
        windows.FILE_ATTRIBUTE_NORMAL,
        0,
    )
    if err != nil {
        return nil, err
    }
    return &Client{handle: h}, nil
}

func (c *Client) Close() error {
    return windows.CloseHandle(c.handle)
}

// ─── Data Volume 전용 ─────────────────────────────────────────────────────────

// Attach는 JVCK 포맷으로 Data Volume에 암호화 레이어를 활성화합니다.
// VMK와 replica 설정(use_header/use_footer/metadata_size)을 전달합니다.
// 재부팅 후 재연결 시에는 볼륨의 JVCK metadata에서 encrypted_offset을 복원합니다.
// (자체 포맷을 쓰는 사용자는 별도 IOCTL과 EncryptedOffsetStore 구현을 사용하며,
//  이 SDK가 노출하는 공통 IOCTL은 그대로 재사용할 수 있습니다.)
func (c *Client) Attach(req *JvckVolumeAttachRequest) (*JvckVolumeAttachResponse, error) {
    return deviceControl[JvckVolumeAttachRequest, JvckVolumeAttachResponse](
        c.handle, ioctlJvckAttach, req,
    )
}

// Detach는 Data Volume의 암호화 레이어를 해제합니다.
// 볼륨이 언마운트되거나 잠금이 필요할 때 호출합니다.
func (c *Client) Detach(volumePath string) error {
    _, err := deviceControl[VolumeDetachRequest, struct{}](
        c.handle, ioctlDetach,
        &VolumeDetachRequest{VolumePath: volumePath},
    )
    return err
}

// ─── 공통 (OS Volume / Data Volume 모두 사용) ─────────────────────────────────

// GetStatus는 볼륨의 현재 암호화 상태를 조회합니다.
func (c *Client) GetStatus(volumePath string) (*VolumeStatus, error) {
    return deviceControl[volumeRequest, VolumeStatus](
        c.handle, ioctlGetStatus,
        &volumeRequest{VolumePath: volumePath},
    )
}

// StartEncrypt는 attach된 볼륨의 점진적 암호화를 시작합니다.
// 키는 Attach(또는 OS Volume의 경우 ACPI 핸드오버)에서 이미 설정되어 있습니다.
func (c *Client) StartEncrypt(req *EncryptRequest) error {
    _, err := deviceControl[EncryptRequest, struct{}](
        c.handle, ioctlStartEncrypt, req,
    )
    return err
}

// StartDecrypt는 attach된 볼륨의 점진적 복호화를 시작합니다.
func (c *Client) StartDecrypt(req *DecryptRequest) error {
    _, err := deviceControl[DecryptRequest, struct{}](
        c.handle, ioctlStartDecrypt, req,
    )
    return err
}

// Pause는 진행 중인 암·복호화를 일시 중지합니다.
func (c *Client) Pause(volumePath string) error {
    _, err := deviceControl[volumeRequest, struct{}](
        c.handle, ioctlPause,
        &volumeRequest{VolumePath: volumePath},
    )
    return err
}
```

### 진행률 스트림 (progress.go)

```go
package vck

import "context"

// WatchProgress는 암·복호화 진행률을 채널 스트림으로 반환합니다.
// 내부적으로 goroutine에서 IOCTL_VCK_GET_PROGRESS를 주기적으로 polling합니다.
// ctx 취소, 완료(StateIdle), 또는 일시 중지(StatePaused) 상태 수신 시 채널이 닫힙니다.
func (c *Client) WatchProgress(
    ctx context.Context,
    volumePath string,
) (<-chan ProgressEvent, <-chan error) {
    evCh  := make(chan ProgressEvent, 16)
    errCh := make(chan error, 1)

    go func() {
        defer close(evCh)
        defer close(errCh)
        req := &volumeRequest{VolumePath: volumePath}
        for {
            select {
            case <-ctx.Done():
                return
            default:
            }
            ev, err := deviceControl[volumeRequest, ProgressEvent](
                c.handle, ioctlGetProgress, req,
            )
            if err != nil {
                errCh <- err
                return
            }
            evCh <- *ev
            if ev.State == StateIdle || ev.State == StatePaused {
                // 암·복호화 완료(Idle) 또는 일시 중지(Paused) → polling 종료
                return
            }
        }
    }()

    return evCh, errCh
}
```

---

## sample 컴포넌트

sample의 각 crate는 **최소한의 코드**로 lib의 트레이트를 구현합니다.
비즈니스 로직은 lib에, 설정·알고리즘 선택만 sample에 위치합니다.

---

### sample/common

sample 전용 공유 코드입니다.

```
sample/common/
├── src/
│   ├── lib.rs
│   ├── config.rs       # VckConfig (vck.json VMK/loader 설정 파싱)
│   └── payload.rs      # VckHandoverPayload (HandoverPayload 구현)
└── Cargo.toml
```

**vck.json 구조:**

개발 편의용 sample에서는 VMK와 다음 OS loader 경로만 저장합니다.
JvckMetadata replica는 OS 볼륨 footer에 있으므로 EFI 파일 경로는 더 이상 필요 없습니다.

```json
{
  "partition_guid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "vmk": "<base64-vmk>",
  "osloader": "/EFI/Microsoft/Boot/msbootmgfw.os.efi"
}
```

`osloader` 필드가 없으면 기본값 `/EFI/Microsoft/Boot/msbootmgfw.os.efi`를 사용합니다.

**VckHandoverPayload:**

metadata가 볼륨 footer에 저장되므로 핸드오버에는 **VMK와 대상 partition_guid만** 담습니다.
드라이버는 이 VMK로 볼륨 footer metadata를 복호화하여 FVEK·encrypted_offset·지오메트리를 복원합니다.
핸드오버 페이로드를 소비한 직후 로더/드라이버는 ACPI 버퍼와 지역 복사본의 VMK를 **zeroize**합니다
(아래 "키 수명·zeroize" 참조).

```rust
/// UEFI 로더 → 드라이버 핸드오버 페이로드
#[derive(Serialize, Deserialize)]
pub struct VckHandoverPayload {
    /// 대상 OS 볼륨 식별용 GPT 파티션 GUID
    pub partition_guid: Guid,
    /// 볼륨 footer metadata 복호화 및 FVEK 복원용 키
    pub vmk: Vec<u8>,
}

impl HandoverPayload for VckHandoverPayload {
    const ACPI_SIGNATURE: [u8; 4] = *b"VCKD";
    const ACPI_OEM_ID:    [u8; 6] = *b"SAMPLE";
}
```

**키 수명·zeroize:** ACPI 핸드오버 버퍼는 `EfiRuntimeServicesData`에 평문 VMK를 담으므로,
드라이버는 부팅 시 VMK를 자체 보호 메모리로 복사한 뒤 ACPI 버퍼를 즉시 zeroize하고, 로더 측
지역 변수(VMK·FVEK)도 사용 후 zeroize합니다. FVEK는 핸드오버에 싣지 않습니다.

---

### sample/driver

`VolumeProvider`를 구현하는 드라이버 샘플입니다.

```
sample/driver/
├── src/
│   ├── lib.rs           # DriverEntry
│   └── provider.rs      # VckVolumeProvider: VolumeProvider 구현
└── Cargo.toml
```

**VckVolumeProvider:**

```rust
pub struct VckVolumeProvider;

impl VolumeProvider for VckVolumeProvider {
    type Payload = VckHandoverPayload;

    async fn on_attach(&self, ctx: &AttachContext<'_, VckHandoverPayload>) -> VckResult<IoConfig> {
        // 1. 핸드오버 페이로드 확보 (lib/driver가 이미 VckHandoverPayload로 역직렬화)
        let payload = ctx.handover_data.ok_or(VckError::NoHandoverData)?;

        // 2. 파티션 GUID 확인
        if ctx.volume_id.partition_guid != payload.partition_guid {
            return Ok(IoConfig::Passthrough);
        }

        // 3. 볼륨 footer metadata를 VMK로 열어 FVEK·encrypted_offset·지오메트리 복원.
        //    KernelVolumeIo(SectorIo 구현)로 raw 섹터 접근을 만든 뒤 generic store를 연다.
        //    동일 store가 encrypted_offset 영속화(footer replica 갱신)도 담당.
        let io = KernelVolumeIo::open(ctx.volume_id, ctx.sector_size, ctx.volume_sectors)?;
        let store = JvckMetadataStore::open(io, &payload.vmk)?;
        let meta = store.load_metadata()?;

        Ok(IoConfig::AesXts {
            key1: meta.fvek_key1,
            key2: meta.fvek_key2,
            offset_sector: store.offset_sector(),
            encrypted_offset: EncryptedOffset {
                sector: meta.encrypted_offset,
                total_sectors: store.data_sector_count(),
            },
            offset_store: Arc::new(store),
        })
    }

    async fn on_detach(&self, _ctx: &DetachContext<'_>) -> VckResult<()> {
        Ok(())
    }
}

impl IoctlAuthorization for VckVolumeProvider {
    fn authorize(&self, ctx: &IoctlAuthContext<'_>) -> VckResult<()> {
        if ctx.ioctl_code == IOCTL_VCK_GET_PROGRESS {
            return Ok(());
        }
        require_administrator(ctx.requestor_token)
    }
}
```

---

### sample/loader

`LoaderProvider`를 구현하는 UEFI 로더 샘플입니다.

```
sample/loader/
├── src/
│   ├── main.rs          # UEFI efi_main 진입점
│   └── provider.rs      # VckLoaderProvider: LoaderProvider 구현
└── Cargo.toml
```

**VckLoaderProvider:**

```rust
pub struct VckLoaderProvider;

impl LoaderProvider for VckLoaderProvider {
    type Payload = VckHandoverPayload;

    fn on_init(&self, boot_services: &BootServices) -> VckResult<LoaderConfig<Self::Payload>> {
        // 1. (EFI)/vck.json에서 VMK와 다음 OS loader 경로 읽기
        let config = VckConfig::load_from_esp(boot_services)?;

        // 2. 대상 OS 볼륨을 Block IO로 열고 footer metadata replica를 읽어 VMK로 복호화
        let store = JvckMetadataStore::open_volume_footer_uefi(
            boot_services,
            config.partition_guid,
            &config.vmk,
        )?;
        let meta = store.load_metadata()?;

        // 3. 핸드오버에는 VMK와 partition_guid만 싣는다. (FVEK/지오메트리는 드라이버가
        //    동일 footer metadata를 VMK로 다시 복호화하여 복원)
        let payload = VckHandoverPayload {
            partition_guid: config.partition_guid,
            vmk:            config.vmk.clone(),
        };

        // 4. 로더 자신의 transparent 복호화용 LoaderCrypto는 방금 읽은 metadata에서 구성
        Ok(LoaderConfig {
            handover_payload: payload,
            next_loader:      config.osloader_device_path(boot_services)?,
            crypto: Some(LoaderCrypto {
                key1:             meta.fvek_key1,
                key2:             meta.fvek_key2,
                offset_sector:    store.offset_sector(),
                encrypted_offset: EncryptedOffset {
                    sector:        meta.encrypted_offset,
                    total_sectors: store.data_sector_count(),
                },
            }),
        })
    }
}
```

---

### sample/app

시스템 볼륨 암호화 관리용 CLI 애플리케이션입니다. **Go**로 작성되며
`github.com/jc-lab/volumecrypt-kit/sdk` 패키지만 사용하여 드라이버와 통신합니다.

```
sample/app/
├── main.go
└── cmd/
    ├── root.go        # cobra 루트 커맨드, 글로벌 플래그 (--volume)
    ├── encrypt.go     # encrypt 서브커맨드
    ├── decrypt.go     # decrypt 서브커맨드
    └── status.go      # status 서브커맨드
```

**명령어:**

```
vck-app os-volume encrypt --volume \\.\C:
vck-app data-volume attach --volume \\.\D: --vmk <base64> --use-header 1 --use-footer 1 --metadata-size 131072
vck-app data-volume encrypt --volume \\.\D:
vck-app decrypt --volume \\.\C:
vck-app status  --volume \\.\C:
```

**data-volume attach 예시 (기본 JVCK 포맷):**

```go
if _, err := client.Attach(&vck.JvckVolumeAttachRequest{
    VolumePath:   volumeFlag,
    VMK:          vmk,
    UseHeader:    useHeaderFlag,
    UseFooter:    useFooterFlag,
    MetadataSize: metadataSizeFlag,
}); err != nil {
    return err
}
```

**encrypt.go 예시 (최소 구현):**

```go
package cmd

import (
    "context"
    "fmt"

    "github.com/jc-lab/volumecrypt-kit/sdk"
    "github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
    Use:   "encrypt",
    Short: "attach된 볼륨의 점진적 암호화 시작",
    RunE: func(cmd *cobra.Command, args []string) error {
        client, err := vck.Open()
        if err != nil {
            return fmt.Errorf("드라이버 연결 실패: %w", err)
        }
        defer client.Close()

        if err := client.StartEncrypt(&vck.EncryptRequest{
            VolumePath: volumeFlag,
        }); err != nil {
            return err
        }

        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()
        evCh, errCh := client.WatchProgress(ctx, volumeFlag)
        for ev := range evCh {
            fmt.Printf("\r암호화 중: %.1f%% (%d / %d 섹터)",
                ev.ProgressPercent(), ev.EncryptedSector, ev.TotalSectors)
        }
        if err := <-errCh; err != nil {
            return err
        }
        fmt.Println("\n암호화 완료.")
        return nil
    },
}
```

**status.go 예시:**

```go
var statusCmd = &cobra.Command{
    Use:   "status",
    Short: "볼륨 암호화 상태 조회",
    RunE: func(cmd *cobra.Command, args []string) error {
        client, err := vck.Open()
        if err != nil {
            return err
        }
        defer client.Close()

        st, err := client.GetStatus(volumeFlag)
        if err != nil {
            return err
        }
        fmt.Printf("볼륨    : %s\n", st.VolumePath)
        fmt.Printf("상태    : %s\n", st.State)
        fmt.Printf("진행률  : %.2f%% (%d / %d 섹터)\n",
            st.ProgressPercent(), st.EncryptedSector, st.TotalSectors)
        return nil
    },
}
```

---

## 전체 동작 흐름

### 시스템 볼륨 부팅 흐름

```
[펌웨어 UEFI]
      │  EFI Boot Entry → sample/loader
      ▼
[sample/loader]
  1. (EFI)/vck.json에서 VMK와 다음 OS loader 경로 읽기
  2. lib/loader: 대상 OS 볼륨을 Block IO로 열어 footer metadata replica 읽기
     lib/common: VMK로 복호화 → FVEK, encrypted_offset, 지오메트리 복원
  3. lib/loader: EFI_BLOCK_IO_PROTOCOL 후킹 → OS 볼륨 데이터 영역 투명(transparent) 암·복호화
  4. lib/loader: VckHandoverPayload(partition_guid, vmk) → msgpack 직렬화
                 EfiRuntimeServicesData 메모리 할당, ACPI 테이블(VCKD) 추가 (물리 주소 기록)
                 로더 지역 FVEK/VMK 사본 사용 후 zeroize
  5. msbootmgfw.os.efi 체인로드 → Windows Boot Manager 기동
      │
      ▼
[Windows Kernel Boot]
  sample/driver DriverEntry
  1. lib/driver: ACPI 테이블(VCKD) 탐색 → VckHandoverPayload(partition_guid, vmk) 역직렬화
     VMK를 보호 메모리로 복사 후 ACPI 버퍼 zeroize (EFI 접근 없음)
  2. PnP 볼륨 도착 → VckVolumeProvider::on_attach
     VMK로 볼륨 footer metadata 복호화 → FVEK·encrypted_offset·지오메트리 복원
     → IoConfig::AesXts 반환
  3. 시스템 볼륨 필터 드라이버 attach, VolumeAttachRegistry 등록
  4. 이후 모든 볼륨 I/O: lib/driver가 비동기 파이프라인으로 처리
     (encrypted_offset 영속화 시에만 볼륨 footer replica를 VMK 파생 키로 갱신)
      │
      ▼
[Windows 정상 부팅 완료]
```

### 점진적 암호화 흐름 (Go app → Rust driver)

```
[vck-app encrypt (Go)]
      │  vck.Client.StartEncrypt(EncryptRequest{volume_path})
      │    → DeviceIoControl(IOCTL_VCK_START_ENCRYPT, msgpack)
      ▼
[sample/driver (Rust)]
      │  IOCTL 디스패치 → EncryptionEngine::start_progress() 비동기 스폰
      │  즉시 OK 반환
      ▼
[vck-app: WatchProgress goroutine]
      루프: DeviceIoControl(IOCTL_VCK_GET_PROGRESS) ← 논블로킹 polling
              │
              ├─ 드라이버: 현재 진행률 스냅샷 즉시 반환
              │   ProgressEvent msgpack → 출력 버퍼
              │
              └─ Go: ProgressEvent 수신 → channel 전송 → stdout 진행률 출력
      │
      ▼
  encrypted_offset == total_sectors
      드라이버: StateIdle ProgressEvent 반환
      Go: channel 종료 → "암호화 완료" 출력
```

---

## 의존성

### Rust (Cargo)

> 의존성의 단일 진실 공급원(SSOT)은 `Cargo.toml`입니다. 아래 표는 설명용이며 버전은 `Cargo.toml`을 따릅니다.

| 크레이트 | 용도 |
|---|---|
| `wdk` / `wdk-sys` | Windows 커널 드라이버 개발 (driver crate 전용) |
| `uefi` | UEFI 애플리케이션 개발 (loader crate 전용) |
| `messagepack-serde` | UEFI↔Driver / IOCTL msgpack 직렬화 (no_std) |
| `serde` | 직렬화 파생 매크로 (no_std, alloc) |
| `aes` + `xts-mode` | AES-XTS 볼륨 암호화 |
| `cbc` + `cipher` | JVCK EncryptedMetadata AES-256-CBC 처리 |
| `sha2` / `hmac` / `hkdf` | JVCK 메타데이터 HMAC 및 키 파생 |
| `crc32fast` | JVCK Metadata 블록 Header CRC32 |
| `uuid` | JVCK Volume ID (UUIDv4) |
| `spin` | no_std 환경 Mutex (커널/UEFI 공용) |
| `irql` | 커널 IRQL 관리 |
| `thiserror` | 에러 타입 정의 (no_std 호환) |

### Go (go.mod)

| 패키지 | 용도 |
|---|---|
| `golang.org/x/sys/windows` | `DeviceIoControl`, `CreateFile` 등 Win32 API |
| `github.com/vmihailenco/msgpack/v5` | IOCTL msgpack 직렬화 |
| `github.com/spf13/cobra` | CLI 커맨드 프레임워크 (`sample/app`만 사용) |

---

## 주요 설계 원칙

**최소 sample 원칙:** sample의 각 crate는 트레이트 구현과 설정 로딩만 담당합니다.
I/O 라우팅, 암·복호화 파이프라인, 핸드오버 직렬화, ACPI 조작 등 모든 메커니즘은 lib에 위치합니다.

**Go/Rust 언어 경계:** 커널 코드(driver, loader)는 Rust+WDK로 구현하고,
유저스페이스 관리 도구(app)는 Go로 구현합니다. 두 언어 간 인터페이스는
`DeviceIoControl` + msgpack으로 명확히 분리되어, 어느 쪽도 상대 언어의 런타임에 의존하지 않습니다.
`sdk`는 Go 관점에서의 드라이버 인터페이스 명세이며, `lib/driver/src/ioctl/`은
Rust 관점에서의 동일한 명세입니다.

**두 가지 I/O 경로:** `IoConfig::Passthrough`를 반환하면 해당 볼륨은 attach하지 않습니다.
`IoConfig::AesXts`(고수준)을 반환하면 lib이 모든 암·복호화를 처리합니다.
`IoConfig::Custom`(저수준)을 반환하면 sample의 `IoHooks` 구현이 섹터 단위로 직접 처리합니다.
`IoConfig::Custom`/`IoHooks`는 Rust 트레이트이므로 컴파일타임에 결정됩니다. 따라서 저수준 커스텀
포맷은 자체 `VolumeProvider`(OS Volume)나 자체 attach IOCTL(Data Volume)을 구현해 사용하며,
`sdk`가 노출하는 `IOCTL_JVCK_ATTACH`/`JvckVolumeAttachRequest`는 JVCK 기본 포맷 전용입니다.

**비동기 설계:** 드라이버 레이어의 모든 I/O는 IRP completion callback 기반의 커널 전용 비동기 실행기를 통해 처리됩니다. 스레드 블로킹 없이 고성능 병렬 암·복호화를 달성합니다.
Go app의 `WatchProgress`는 goroutine에서 논블로킹 진행률 IOCTL을 polling하여 Go 채널 스트림으로 변환합니다.

**핸드오버 확장성:** ACPI 테이블 서명과 msgpack 페이로드 구조는 sample에서 결정합니다.
`LoaderProvider::Payload`와 `VolumeProvider::Payload`를 동일한 `HandoverPayload` 구현 타입으로
지정하면, lib/loader는 그 타입으로 직렬화하고 lib/driver는 그 타입으로 역직렬화하여
`AttachContext`에 구체 타입으로 전달합니다(`dyn Any` downcast 불필요). lib은 직렬화·ACPI
기록·읽기 헬퍼만 제공하므로 다른 sample이 독립적인 핸드오버 스킴을 가질 수 있습니다.

**점진적 암호화 안전성:** 암호화 중 전원이 꺼지더라도 `EncryptedOffsetStore`가 `encrypted_offset`을 영속적으로 관리하므로
재부팅 후 중단된 지점부터 재개할 수 있습니다. 기본 JVCK 구현은 header/footer replica에 중복 저장하며,
사용자는 같은 trait으로 자기만의 저장 포맷을 구현할 수 있습니다. `encrypted_offset` 이전은 암호화, 이후는 평문으로
드라이버가 자동 분기 처리합니다.
