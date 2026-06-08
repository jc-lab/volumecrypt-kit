# volumecrypt-kit Architecture

## 개요

`volumecrypt-kit`은 Rust와 WDK(Windows Driver Kit)를 기반으로 하는 볼륨 암호화 라이브러리 키트입니다.
비동기 I/O를 통해 고성능을 달성하고, 명확한 인터페이스(Trait) 구현만으로 손쉽게 볼륨 암호화를 구성할 수 있도록 설계되었습니다.

Low-level 구현 (볼륨 포멧, 암호화 알고리즘 등 모든 부분들을 자체적으로 구현하고, volumecrypt-kit 에서는 volume filter 역할만 담당)과,
High-level 구현 (JvckMetadata 을 이용한 기본 구현) 이 가능합니다.

### OS Volume (시스템 볼륨)

- UEFI 로더가 부팅 전에 Block IO를 후킹하고 ACPI 핸들오버로 키를 드라이버에 전달합니다.
- 드라이버는 부팅 시 핸드오버된 데이터가 있으면 자동으로 볼륨에 attach됩니다.

샘플 구현 (JvckMetadata 사용):
- `(EFI)/vck.json` 에 평문 VMK 와 로더 설정을 저장합니다.
- 시스템 볼륨은 볼륨 header를 사용할 수 없으므로 JvckMetadata 복제본은 `(EFI)/sys1.vck`, `(EFI)/sys2.vck`에 저장합니다.

### Data Volume (데이터 볼륨)

- UEFI가 관여하지 않습니다.
- OS 부팅 후 Go 애플리케이션이 `IOCTL_VCK_ATTACH`를 통해 볼륨 경로와 VMK 을 드라이버에 제공하여 암호화 레이어를 활성화합니다.
- 새롭게 파티션을 생성 할 경우 UseHeader=1, UseFooter=2 을 사용하고, 기존 파티션을 암호화 할 경우 Shrink 하여 Metadata 공간을 확보하여 UseHeader=0, UseFooter=2 을 사용합니다.
- 볼륨의 첫 4byte 을 보고 Metadata 존재 유무를 파악하고, 없을 경우 맨 뒤 섹터부터 최대 1MB 만큼까지 역순으로 Metadata 을 찾습니다.

---

## 저장소 구조

```
volumecrypt-kit/
├── lib/                         # Rust: 라이브러리 계층
│   ├── common/                  # 공통 타입, 에러, msgpack 핸들오버 헬퍼, JVCK 기본 metadata 포맷 (JvckMetadata) 에 대한 구현들
│   ├── driver/                  # 커널 드라이버 프레임워크 (WDK, 비동기 I/O, encrypted_offset)
│   └── loader/                  # UEFI 로더 프레임워크 (Block IO 후킹, ACPI 핸들오버)
│
├── sdk/                         # Go: 유저스페이스 SDK
│   └── vck/                     # 드라이버 IOCTL 클라이언트 라이브러리
│
├── sample/                      # JVCK 기본 metadata 포맷 (JvckMetadata) 만을 사용하는 예제
│   ├── common/                  # Rust: vck.json(VMK/loader 설정) 파싱, JVCK 메타데이터, 핸들오버 페이로드 정의
│   ├── driver/                  # Rust: VolumeProvider 구현체 (AES-XTS)
│   ├── loader/                  # Rust: UEFI 로더 구현체
│   └── app/                     # Go: 관리용 CLI (OS/Data 볼륨 attach·암호화·복호화·상태 조회)
│
├── Cargo.toml                   # Rust workspace
├── go.mod                       # Go module root (github.com/jc-lab/volumecrypt-kit)
├── go.sum
└── ARCH.md
```

### 언어별 모듈 경계

| 언어 | 범위 | 빌드 단위 |
|---|---|---|
| Rust | `lib/`, `sample/common`, `sample/driver`, `sample/loader` | Cargo workspace |
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
- UEFI→Driver 핸들오버 추상화
  - `HandoverPayload` 트레이트: `rmp-serde`를 통한 직렬화/역직렬화 인터페이스
  - `AcpiHandoverWriter` (로더 측): `EfiRuntimeServicesData`로 msgpack 버퍼를 할당하고 커스텀 ACPI 테이블에 물리 주소를 기록
  - `AcpiHandoverReader` (드라이버 측): ACPI 테이블에서 물리 주소를 읽어 msgpack 버퍼를 역직렬화
- 공통 상수 및 유틸리티

```
lib/common/
├── src/
│   ├── lib.rs
│   ├── error.rs           # VckError, VckResult
│   ├── types.rs           # EncryptedOffset, SectorRange, VolumeId, ...
│   └── handover/
│       ├── mod.rs
│       ├── payload.rs     # HandoverPayload trait
│       ├── writer.rs      # AcpiHandoverWriter (UEFI 측)
│       └── reader.rs      # AcpiHandoverReader (Driver 측)
└── Cargo.toml
```

**핵심 타입:**

```rust
/// 점진적 암호화 진행 상태
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedOffset {
    /// 이 섹터 이전까지는 암호화 완료
    pub sector: u64,
    /// 전체 볼륨 섹터 수
    pub total_sectors: u64,
}

impl EncryptedOffset {
    pub fn is_encrypted(&self, sector: u64) -> bool {
        sector < self.sector
    }
    pub fn is_fully_encrypted(&self) -> bool {
        self.sector >= self.total_sectors
    }
}

/// UEFI → Driver 핸들오버 페이로드 트레이트
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
pub const IOCTL_VCK_GET_STATUS:    u32 = 0x0022_2000; // Function = 0x800
pub const IOCTL_VCK_START_ENCRYPT: u32 = 0x0022_2004; // Function = 0x801
pub const IOCTL_VCK_START_DECRYPT: u32 = 0x0022_2008; // Function = 0x802
pub const IOCTL_VCK_GET_PROGRESS:  u32 = 0x0022_200c; // Function = 0x803
pub const IOCTL_VCK_PAUSE:         u32 = 0x0022_2010; // Function = 0x804
pub const IOCTL_VCK_ATTACH:        u32 = 0x0022_2014; // Function = 0x805 (Data Volume용)
pub const IOCTL_VCK_DETACH:        u32 = 0x0022_2018; // Function = 0x806 (Data Volume용)
```

**IOCTL 입출력 포맷:** 입력 버퍼와 출력 버퍼 모두 msgpack(`rmp-serde`)을 사용합니다.
Go SDK와 Rust 드라이버 사이의 구조체 정의는 아래 sdk 섹션에서 설명합니다.

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
│    AcpiHandoverReader → VckHandoverPayload (key, enc_offset)    │
│         │                                                       │
│  [PnP 볼륨 도착 알림]                                           │
│    VolumeProvider::on_attach(AttachContext { source: Handover })│
│         → IoConfig::AesXts 반환                              │
│         → VolumeAttachRegistry에 등록                           │
│         → 필터 드라이버 스택에 삽입                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       Data Volume (일반)                         │
│                                                                 │
│  [IOCTL_VCK_ATTACH 수신]                                        │
│    VolumeAttachIoctlReq { volume_path, vmk 또는 key1/key2,       │
│                           offset_sector, encrypted_sector,      │
│                           total_sectors }                       │
│         │                                                       │
│    lib/driver가 JVCK 또는 사용자 포맷으로 IoConfig 구성          │
│    (VMK로 JVCK 메타데이터를 열거나, key1/key2 직접 제공)         │
│         → VolumeAttachRegistry에 등록                           │
│         → 필터 드라이버 스택에 삽입                              │
│         ← VolumeAttachIoctlResp { offset_sector, total_sectors, │
│                                   sector_size }                 │
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
    /// OS Volume: ACPI 핸들오버로 자동 attach
    Handover,
    /// Data Volume: IOCTL_VCK_ATTACH로 런타임 attach
    Ioctl,
}
```

**VolumeProvider 트레이트 (핵심 인터페이스):**

```rust
/// OS Volume의 부팅 시 attach 콜백. Data Volume은 사용하지 않습니다.
pub trait VolumeProvider: Send + Sync + 'static {
    /// 볼륨 attach 시 호출 (OS Volume 전용).
    /// IoConfig를 반환하여 암호화 방식을 결정합니다.
    async fn on_attach(&self, ctx: &AttachContext<'_>) -> VckResult<IoConfig>;

    /// 볼륨 detach 시 호출 (OS Volume 전용).
    async fn on_detach(&self, ctx: &DetachContext<'_>) -> VckResult<()>;
}

/// Attach 시 반환하는 I/O 동작 설정
pub enum IoConfig {
    /// 이 볼륨에는 필터를 attach하지 않고 그대로 통과
    Passthrough,

    /// 고수준: lib/driver 내부에서 AES-XTS로 자동 처리
    AesXts {
        key1: [u8; 32],
        key2: [u8; 32],
        encrypted_offset: EncryptedOffset,
        offset_store: Arc<dyn EncryptedOffsetStore>,
    },

    /// 저수준: sample이 직접 Read/Write 훅 구현
    Custom {
        io_hooks: Arc<dyn IoHooks>,
        encrypted_offset: EncryptedOffset,
        offset_store: Arc<dyn EncryptedOffsetStore>,
    },
}

/// 저수준 I/O 훅 인터페이스
pub trait IoHooks: Send + Sync + 'static {
    async fn read(&self, sector: u64, buf: &mut [u8]) -> VckResult<()>;
    async fn write(&self, sector: u64, buf: &[u8]) -> VckResult<()>;
}

pub struct AttachContext<'a> {
    pub volume_id:      &'a VolumeId,
    pub sector_size:    u32,
    pub offset_sector:  u64,
    pub total_sectors:  u64,
    /// 핸들오버에서 읽어온 드라이버 전달 데이터
    pub handover_data:  Option<&'a dyn Any>,
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
        IOCTL_VCK_ATTACH => handle_attach(ctx),
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

```
[볼륨 Attach]
     │
     ▼
EncryptionEngine::new(encrypted_offset, total_sectors)
     │
     ├─ Read(sector) ──────────────────────────────────────────────────────┐
     │   sector < encrypted_offset  →  AES-XTS 복호화 후 반환              │
     │   sector >= encrypted_offset →  평문 그대로 반환                    │
     │                                                                     │
     ├─ Write(sector) ─────────────────────────────────────────────────────┤
     │   sector < encrypted_offset  →  AES-XTS 암호화 후 하위 드라이버로  │
     │   sector >= encrypted_offset →  평문 그대로 하위 드라이버로         │
     │                                                                     │
     └─ ProgressEncryption() ──────────────────────────────────────────────┘
         배치 단위로 encrypted_offset 이후 섹터를 읽어
         AES-XTS 암호화 후 기록, offset_store.store()/flush()로 encrypted_offset 영속화
```

**JvckMetadata(JVCK 기본 메타데이터) 포맷 (lib 제공):**

lib은 Data Volume과 OS Volume 모두에서 사용할 수 있는 기본 메타데이터 포맷을 제공합니다.
사용자는 이 포맷을 그대로 쓰거나 `EncryptedOffsetStore`와 attach 로직을 직접 구현하여
자기만의 포맷을 사용할 수 있습니다. 기본 JVCK 포맷을 사용할 경우 VMK 입력이 필요합니다.
Data Volume은 header/footer replica를 사용할 수 있습니다. System Volume은 OS 볼륨 앞부분에
header를 둘 수 없으므로 `(EFI)/sys1.vck`, `(EFI)/sys2.vck` 파일을 동일 내용 복제본으로 사용합니다.

드라이버에서 지정 가능한 기본 포맷 옵션은 다음과 같습니다.

```rust
pub struct JvckMetadataOptions {
    /// 볼륨 header 영역에 중복 저장할 metadata replica 개수
    pub use_header: u32,
    /// 볼륨 footer 영역에 중복 저장할 metadata replica 개수
    pub use_footer: u32,
    /// replica 하나의 크기. 최소 128KiB.
    pub metadata_size: u32,
}
```

`metadata_size`는 최소 128KiB입니다. Data Volume에서는 `use_header + use_footer >= 1`이어야 합니다.
Header replica는 볼륨 시작부터 순서대로 배치하고, Footer replica는 볼륨 끝에서 역순으로
배치합니다. 암호화 대상 데이터 영역은 header/footer metadata 영역을 제외한
`offset_sector..offset_sector + total_sectors`입니다. System Volume에서는 `use_header = 0`,
`use_footer = 0`으로 두고 `(EFI)/sys1.vck`, `(EFI)/sys2.vck` 파일 replica를 사용합니다.

Metadata 구조는 다음과 같습니다. 모든 숫자는 little endian이며, 모든 용량 단위는 bytes입니다. `Header CRC32`는 offset 0부터 507까지의 header 영역에 대해 계산합니다.

| Offset | Size | Description |
| ------ | ---- | ----------- |
| 0      | 4    | signature `JVCK` |
| 4      | 8    | Vendor ID |
| 12     | 2    | VCK Metadata Version |
| 14     | 2    | Vendor Specific Version |
| 16     | 4    | Metadata Size (offset 0부터 포함) |
| 20     | 4    | Sector Size (e.g. 512) |
| 24     | 1    | Header replica count |
| 25     | 1    | Footer replica count |
| 26     | 6    | Reserved (zero) |
| 32     | 16   | Volume ID (UUIDv4) |
| 48     | 128  | Encrypted Metadata |
| 176    | 32   | HMAC-SHA256(key = EncryptedMetadata_MAC_KEY, data = 암호화된 EncryptedMetadata) |
| 208    | 300  | Reserved (zero) |
| 508    | 4    | Header CRC32 |
| 512    | end  | Vendor specific data |

**EncryptedMetadata**는 AES-256-CBC(no padding)로 암호화하며,
`EncryptedMetadata_ENC_KEY`, `EncryptedMetadata_ENC_IV`를 사용합니다. 고정 크기는 128바이트입니다.

| Offset | Size | Description |
| ------ | ---- | ----------- |
| 0      | 4    | signature `JVCK` |
| 4      | 12   | must zero (prevent POODLE) |
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

`JvckMetadataStore`는 `EncryptedOffsetStore`를 구현합니다. Data Volume에서는 header/footer replica를,
System Volume에서는 `(EFI)/sys1.vck`, `(EFI)/sys2.vck` 파일 replica를 대상으로 동작합니다.
`store()`는 모든 configured replica에 동일한 encrypted_offset을 기록하고, `load()`는 HMAC 검증에
성공한 replica 중 정책상 가장 최신의 유효 metadata를 선택합니다. 기본 구현은 모든 replica가 같은
값을 갖도록 유지하며, 서로 다른 값이 발견되면 가장 큰 `encrypted_offset`을 선택하되 운영 로그에
replica mismatch를 남깁니다.

---

### lib/loader

UEFI 환경에서 동작하는 로더 프레임워크입니다. `uefi` crate 기반입니다.

**주요 역할:**

- `LoaderProvider` 트레이트 정의 (로더가 sample에게 요구하는 인터페이스)
- `EFI_BLOCK_IO_PROTOCOL` 및 `EFI_BLOCK_IO2_PROTOCOL` 후킹 엔진
- UEFI→Driver 핸들오버 데이터 기록 (`AcpiHandoverWriter` 래퍼)
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

    /// 로더 초기화 시 호출. 암호화 설정 및 핸들오버 페이로드 반환
    fn on_init(&self, boot_services: &BootServices) -> VckResult<LoaderConfig<Self::Payload>>;

    /// Block IO Read 훅 (고수준 선택 시 lib가 AES-XTS 자동 처리)
    fn read_hook(&self, lba: u64, buf: &mut [u8]) -> VckResult<()> {
        // 기본 구현: 훅 없음 (고수준 경로에서는 lib이 처리)
        Ok(())
    }
}

pub struct LoaderConfig<P: HandoverPayload> {
    /// 드라이버로 전달할 핸들오버 데이터
    pub handover_payload: P,
    /// 체인로드할 다음 EFI 바이너리 경로
    pub next_loader: DevicePath,
    /// AES-XTS 키 (고수준 경로, None이면 read_hook 사용)
    pub crypto: Option<LoaderCrypto>,
}

pub struct LoaderCrypto {
    pub key1: [u8; 32],
    pub key2: [u8; 32],
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
                ├─ lba < encrypted_offset  →  원본 Read 후 AES-XTS 복호화
                └─ lba >= encrypted_offset →  원본 Read 그대로 반환
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
    golang.org/x/sys v0.x.x
    github.com/vmihailenco/msgpack/v5 v5.x.x
)
```

`sdk`는 `golang.org/x/sys/windows`만 외부 의존성으로 사용합니다.

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

// VolumeAttachRequest는 IOCTL_VCK_ATTACH 요청 구조체입니다.
// Data Volume을 드라이버에 등록하고 암호화 레이어를 활성화합니다.
type VolumeAttachRequest struct {
    // Required. 볼륨 경로. 예: \\.\D:  또는  \\?\Volume{9b951408-f281-4b15-a72c-ffe44bbae057}\
    VolumePath      string   `msgpack:"volume_path"`
    // Optional(JVCK). 기본 JVCK 포맷을 사용할 때 필요한 VMK. 사용자 포맷 사용 시 비울 수 있습니다.
    VMK             []byte   `msgpack:"vmk,omitempty"`
    // Optional. 실제 암호화 대상 영역 시작 섹터. 자체 header가 있으면 그 이후를 지정.
	// JVCK 포맷 사용시 불필요하며 암호화 영역은 offset=UseHeader*MetadataSize, size=capacity-offset-UseFooter*MetadataSize 임.
    OffsetSector    uint64   `msgpack:"offset_sector"`
    // Optional. 암호화 대상 영역 섹터 수. 0이면 offset 이후 footer 전까지 자동 감지.
    TotalSectors    uint64   `msgpack:"total_sectors"`
    // Optional. 이미 암호화된 섹터 수. 처음 암호화라면 0.
    EncryptedSector uint64   `msgpack:"encrypted_sector"`
    // Required. JVCK 기본 metadata 포맷 사용 여부 및 replica 설정.
    UseJvckMetadata bool     `msgpack:"use_jvck_metadata"`
    // Optional(JVCK)
    UseHeader       uint32   `msgpack:"use_header"`
    // Optional(JVCK)
    UseFooter       uint32   `msgpack:"use_footer"`
    // Optional(JVCK)
    MetadataSize    uint32   `msgpack:"metadata_size"`
}

// VolumeAttachResponse는 IOCTL_VCK_ATTACH 응답 구조체입니다.
type VolumeAttachResponse struct {
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
    ioctlAttach       = 0x0022_2014 // Data Volume: 암호화 레이어 활성화
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

// Attach는 Data Volume에 암호화 레이어를 활성화합니다.
// 기본 JVCK 포맷을 쓰면 VMK와 metadata replica 설정을 전달합니다.
// 사용자 포맷을 쓰는 경우 key1/key2, offset_sector, encrypted_sector를 직접 전달할 수 있습니다.
// 재부팅 후 재연결 시에는 JVCK 또는 사용자 EncryptedOffsetStore에서 encrypted_sector를 복원합니다.
func (c *Client) Attach(req *VolumeAttachRequest) (*VolumeAttachResponse, error) {
    return deviceControl[VolumeAttachRequest, VolumeAttachResponse](
        c.handle, ioctlAttach, req,
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
    return deviceControl[statusRequest, VolumeStatus](
        c.handle, ioctlGetStatus,
        &statusRequest{VolumePath: volumePath},
    )
}

// StartEncrypt는 attach된 볼륨의 점진적 암호화를 시작합니다.
// 키는 Attach(또는 OS Volume의 경우 ACPI 핸들오버)에서 이미 설정되어 있습니다.
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
    _, err := deviceControl[statusRequest, struct{}](
        c.handle, ioctlPause,
        &statusRequest{VolumePath: volumePath},
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
// ctx 취소 또는 완료 상태 수신 시 채널이 닫힙니다.
func (c *Client) WatchProgress(
    ctx context.Context,
    volumePath string,
) (<-chan ProgressEvent, <-chan error) {
    evCh  := make(chan ProgressEvent, 16)
    errCh := make(chan error, 1)

    go func() {
        defer close(evCh)
        defer close(errCh)
        req := &statusRequest{VolumePath: volumePath}
        for {
            select {
            case <-ctx.Done():
                return
            default:
            }
            ev, err := deviceControl[statusRequest, ProgressEvent](
                c.handle, ioctlGetProgress, req,
            )
            if err != nil {
                errCh <- err
                return
            }
            evCh <- *ev
            if ev.State == StateIdle {
                // 암·복호화 완료 또는 일시 중지됨
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
│   ├── config.rs       # VckConfig (vck.json VMK/loader/sys metadata 파일 파싱)
│   └── payload.rs      # VckHandoverPayload (HandoverPayload 구현)
└── Cargo.toml
```

**vck.json 구조:**

개발 편의용 sample에서는 VMK와 다음 OS loader 경로, System Volume JVCK replica 파일 경로만 저장합니다.

```json
{
  "partition_guid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "vmk": "<base64-vmk>",
  "osloader": "/EFI/Microsoft/Boot/msbootmgfw.os.efi",
  "system_metadata_files": [
    "sys1.vck",
    "sys2.vck"
  ],
  "metadata_size": 131072
}
```

`osloader` 필드가 없으면 기본값 `/EFI/Microsoft/Boot/msbootmgfw.os.efi`를 사용합니다.
`system_metadata_files` 필드가 없으면 기본값은 `sys1.vck`, `sys2.vck`입니다.
`system_metadata_files` 는 vck.json 과 동일한 볼륨(EFI)을 기준으로 합니다.

**VckHandoverPayload:**

```rust
/// UEFI 로더 → 드라이버 핸들오버 페이로드
#[derive(Serialize, Deserialize)]
pub struct VckHandoverPayload {
    pub partition_guid: Guid,
    pub offset_sector: u64,
    pub total_sectors: u64,
    pub volume_id: [u8; 16],
    pub vmk: Vec<u8>,
    pub system_metadata_files: Vec<String>,
    pub metadata_size: u32,
}

impl HandoverPayload for VckHandoverPayload {
    const ACPI_SIGNATURE: [u8; 4] = *b"VCKD";
    const ACPI_OEM_ID:    [u8; 6] = *b"SAMPLE";
}
```

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
    async fn on_attach(&self, ctx: &AttachContext<'_>) -> VckResult<IoConfig> {
        // 1. 핸들오버 데이터에서 VckHandoverPayload 추출
        let payload: &VckHandoverPayload = ctx.handover_data
            .and_then(|d| d.downcast_ref())
            .ok_or(VckError::NoHandoverData)?;

        // 2. 파티션 GUID 확인
        if ctx.volume_id.partition_guid != payload.partition_guid {
            return Ok(IoConfig::Passthrough);
        }

        // 3. System Volume JVCK 파일 replica를 VMK로 열어 FVEK와 encrypted_offset 복원
        let store = JvckMetadataStore::open_system_files(
            ctx.volume_id,
            &payload.vmk,
            &payload.system_metadata_files,
            payload.metadata_size,
        )?;
        let meta = store.load_metadata()?;

        Ok(IoConfig::AesXts {
            key1: meta.fvek_key1,
            key2: meta.fvek_key2,
            encrypted_offset: EncryptedOffset {
                sector: meta.encrypted_offset,
                total_sectors: ctx.total_sectors,
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
        // 1. (EFI)/vck.json에서 VMK와 System Volume metadata 파일 경로 읽기
        let config = VckConfig::load_from_esp(boot_services)?;

        // 2. 핸들오버 페이로드 구성
        let store = JvckMetadataStore::open_system_files_uefi(
            config.partition_guid,
            &config.vmk,
            &config.system_metadata_files,
            config.metadata_size,
        )?;
        let meta = store.load_metadata()?;

        let payload = VckHandoverPayload {
            partition_guid:    config.partition_guid,
            offset_sector:     store.offset_sector(),
            total_sectors:     store.data_sector_count(),
            volume_id:         meta.volume_id,
            vmk:                   config.vmk.clone(),
            system_metadata_files: config.system_metadata_files.clone(),
            metadata_size:         config.metadata_size,
        };

        Ok(LoaderConfig {
            handover_payload: payload,
            next_loader:      config.osloader_device_path(boot_services)?,
            crypto: Some(LoaderCrypto {
                key1:             meta.fvek_key1,
                key2:             meta.fvek_key2,
                encrypted_offset: EncryptedOffset {
                    sector:        meta.encrypted_offset,
                    total_sectors: payload.total_sectors,
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
if _, err := client.Attach(&vck.VolumeAttachRequest{
    VolumePath:      volumeFlag,
    VMK:             vmk,
    UseJvckMetadata: true,
    UseHeader:       useHeaderFlag,
    UseFooter:       useFooterFlag,
    MetadataSize:    metadataSizeFlag,
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
  1. (EFI)/vck.json에서 VMK와 System Volume metadata 파일 경로 읽기
  2. lib/common: VMK로 (EFI)/sys1.vck, (EFI)/sys2.vck replica를 열어 FVEK와 encrypted_offset 복원
  3. lib/loader: EFI_BLOCK_IO_PROTOCOL 후킹 (AES-XTS 복호화 레이어 삽입)
  4. lib/loader: VckHandoverPayload → msgpack 직렬화
                 EfiRuntimeServicesData 메모리 할당
                 ACPI 테이블(VCKD) 추가 (물리 주소 기록)
  5. msbootmgfw.os.efi 체인로드 → Windows Boot Manager 기동
      │
      ▼
[Windows Kernel Boot]
  sample/driver DriverEntry
  1. lib/driver: ACPI 테이블(VCKD) 탐색
  2. msgpack 역직렬화 → VckHandoverPayload
  3. VMK로 (EFI)/sys1.vck, (EFI)/sys2.vck replica를 열어 FVEK와 encrypted_offset 복원
  4. 시스템 볼륨 필터 드라이버 attach
  5. VckVolumeProvider::on_attach → IoConfig::AesXts 반환
  5. 이후 모든 볼륨 I/O: lib/driver가 비동기 파이프라인으로 처리
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

| 크레이트 | 용도 |
|---|---|
| `wdk` / `wdk-sys` | Windows 커널 드라이버 개발 |
| `uefi` | UEFI 애플리케이션 개발 |
| `rmp-serde` | UEFI↔Driver msgpack 직렬화 |
| `serde` / `rmp-serde` | 직렬화 파생 매크로, 핸들오버 및 IOCTL msgpack 포맷 |
| `aes` + `xts-mode` | AES-XTS 암호화 |
| `sha2` / `hmac` / `hkdf` | JVCK 메타데이터 HMAC 및 키 파생 |
| `cbc` | JVCK EncryptedMetadata AES-256-CBC 처리 |
| `log` / `uefi-logger` | 로깅 추상화 |
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
I/O 라우팅, 암·복호화 파이프라인, 핸들오버 직렬화, ACPI 조작 등 모든 메커니즘은 lib에 위치합니다.

**Go/Rust 언어 경계:** 커널 코드(driver, loader)는 Rust+WDK로 구현하고,
유저스페이스 관리 도구(app)는 Go로 구현합니다. 두 언어 간 인터페이스는
`DeviceIoControl` + msgpack으로 명확히 분리되어, 어느 쪽도 상대 언어의 런타임에 의존하지 않습니다.
`sdk`는 Go 관점에서의 드라이버 인터페이스 명세이며, `lib/driver/src/ioctl/`은
Rust 관점에서의 동일한 명세입니다.

**두 가지 I/O 경로:** `IoConfig::Passthrough`를 반환하면 해당 볼륨은 attach하지 않습니다.
`IoConfig::AesXts`(고수준)을 반환하면 lib이 모든 암·복호화를 처리합니다.
`IoConfig::Custom`(저수준)을 반환하면 sample의 `IoHooks` 구현이 섹터 단위로 직접 처리합니다.

**비동기 설계:** 드라이버 레이어의 모든 I/O는 IRP completion callback 기반의 커널 전용 비동기 실행기를 통해 처리됩니다. 스레드 블로킹 없이 고성능 병렬 암·복호화를 달성합니다.
Go app의 `WatchProgress`는 goroutine에서 논블로킹 진행률 IOCTL을 polling하여 Go 채널 스트림으로 변환합니다.

**핸들오버 확장성:** ACPI 테이블 서명과 msgpack 페이로드 구조는 sample에서 결정합니다.
lib은 직렬화·ACPI 기록·읽기 헬퍼만 제공하므로 다른 sample이 독립적인 핸들오버 스킴을 가질 수 있습니다.

**점진적 암호화 안전성:** 암호화 중 전원이 꺼지더라도 `EncryptedOffsetStore`가 `encrypted_offset`을 영속적으로 관리하므로
재부팅 후 중단된 지점부터 재개할 수 있습니다. 기본 JVCK 구현은 header/footer replica에 중복 저장하며,
사용자는 같은 trait으로 자기만의 저장 포맷을 구현할 수 있습니다. `encrypted_offset` 이전은 암호화, 이후는 평문으로
드라이버가 자동 분기 처리합니다.
