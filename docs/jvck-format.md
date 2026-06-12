<!--
SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>

SPDX-License-Identifier: Apache-2.0
-->

# JVCK 메타데이터 포맷

JVCK는 키트가 기본 제공하는 온디스크 메타데이터 포맷입니다(`lib/common/src/jvck`). VMK(Volume Master
Key)만 입력하면 FVEK·진행상태(`encrypted_offset`)·지오메트리를 메타데이터에서 복원합니다. 자체 포맷이
필요하면 `EncryptedOffsetStore`와 attach 로직을 직접 구현해 이 포맷을 대체할 수 있습니다.

## replica 배치

메타데이터는 볼륨 자체의 header/footer 영역에 **replica**로 중복 저장됩니다(EFI 파일을 쓰지 않음).
옵션은 다음과 같습니다.

```rust
pub struct JvckMetadataOptions {
    pub use_header: u32,    // header replica 개수 (신규 파티션만 가능)
    pub use_footer: u32,    // footer replica 개수
    pub metadata_size: u32, // replica 한 개 영역 크기(벤더 데이터 포함), 최소 128KiB
}
```

- `use_header + use_footer >= 1`.
- 데이터(암호화 대상) 영역 시작 절대 LBA: `offset_sector = use_header * metadata_size / sector_size`.
- 암호화 대상 `total_sectors`는 header/footer replica 영역을 제외한 부분.

**기존 파티션(OS 볼륨 포함)** 은 파일시스템이 앞부분을 점유하므로 header를 쓸 수 없습니다. 최초 암호화 시
파일시스템을 shrink하여 끝부분에 footer replica 2개를 둡니다(`use_header=0`, `use_footer=2`).
**신규 파티션**만 header replica가 가능합니다(`use_header=1`, `use_footer=2` 등).

**replica 내부 배치** — replica 한 개는 고정 512바이트 **Metadata 블록**과 나머지 **Vendor specific
data**로 구성되며, 탐색을 단순화하기 위해 분리 배치합니다.

- Header replica: `[Metadata(512B)][Vendor data]` — Metadata가 맨 앞.
- Footer replica: `[Vendor data][Metadata(512B)]` — Metadata가 맨 끝.

이렇게 하면 마지막 footer replica의 Metadata가 볼륨 맨 끝 512바이트에 오므로, **볼륨 마지막 섹터만 읽어도**
`JVCK` signature를 즉시 확인할 수 있습니다. (볼륨 첫 4바이트로 header Metadata 유무 판별.)

## Metadata 블록 (512 bytes)

모든 정수는 little-endian, 용량 단위는 bytes. `Header CRC32`는 offset 0..507에 대해 계산합니다.

| Offset | Size | 설명                                                        |
| ------ | ---- |-----------------------------------------------------------|
| 0   | 4   | signature `JVCK`                                          |
| 4   | 8   | **Vendor ID**                                             |
| 12  | 2   | VCK Metadata Version                                      |
| 14  | 2   | **Vendor Specific Version**                               |
| 16  | 4   | Metadata Size (이 replica 영역 전체 크기, 벤더 데이터 포함)             |
| 20  | 4   | Sector Size (예: 512)                                      |
| 24  | 1   | Header replica count                                      |
| 25  | 1   | Footer replica count                                      |
| 26  | 6   | Reserved (zero)                                           |
| 32  | 16  | Volume ID (UUIDv4)                                        |
| 48  | 16  | Salt — 키 파생 salt에 추가; Encrypted Metadata 갱신마다 CSPRNG로 재생성 |
| 64  | 128 | Encrypted Metadata                                        |
| 192 | 32  | HMAC-SHA256(key = MAC_KEY, data = Encrypted Metadata)     |
| 224 | 80  | Reserved (zero)                                           |
| 304 | 192 | **Vendor Specific Reserved** — 벤더 정의(알고리즘 파라미터·추가 키 등)    |
| 496 | 12  | Reserved (zero)                                           |
| 508 | 4   | Header CRC32                                              |

`Salt`는 평문으로 저장되어 복호화 시 읽어 키를 재파생합니다. 매 기록마다 새 salt를 쓰므로 AES-CBC의
키/IV가 같은 볼륨에서 재사용되지 않습니다(Encrypted Metadata 평문 앞부분이 상수라, salt가 없으면 동일
선두 ciphertext 블록이 매번 노출됨). `Vendor Specific Reserved`는 기본 suite에서는 0이며, 벤더 구현이
알고리즘 식별자나 추가 파라미터를 둘 수 있습니다(아래 "Vendor ID 확장" 참조).

Vendor specific data는 Metadata 블록 **밖**(위 replica 배치 참조)에 위치하며 크기는 `metadata_size - 512`.

## Encrypted Metadata (128 bytes)

AES-256-CBC(no padding), 키/IV는 아래 파생값(`ENC_KEY`/`ENC_IV`)을 사용합니다.

| Offset | Size | 설명 |
| ------ | ---- | ---- |
| 0  | 4  | signature `JVCK` |
| 4  | 12 | must zero (복호화 후 0이 아니면 VMK 불일치/손상으로 판정하는 무결성 패턴) |
| 16 | 8  | encrypted_offset |
| 24 | 8  | reserved (zero) |
| 32 | 32 | FVEK Key1 (encryption key) |
| 64 | 32 | FVEK Key2 (tweak key) |
| 96 | 32 | reserved (zero) |

## 키 파생 (HKDF-SHA256)

HKDF salt는 `Volume ID(16B) ‖ Salt(16B)` = 32바이트입니다. Salt가 매 기록마다 바뀌므로 세 키 모두
기록마다 새로 파생됩니다.

```text
MAC_KEY = HKDF_SHA256(salt = Volume ID ‖ Salt, ikm = VMK, info = "EncryptedMetadata:MAC", len = 32)
ENC_KEY = HKDF_SHA256(salt = Volume ID ‖ Salt, ikm = VMK, info = "EncryptedMetadata:ENC", len = 32)
ENC_IV  = HKDF_SHA256(salt = Volume ID ‖ Salt, ikm = VMK, info = "EncryptedMetadata:IV",  len = 16)
```

> 인코더(`encode` / `EncodeMetadataBlock`)는 salt를 인자로 받습니다(테스트 결정성). 런타임에는 드라이버가
> `BCryptGenRandom`(`vck_common::RandomSource`로 주입), 앱은 `crypto/rand`로 salt를 생성합니다. 로더는
> 메타데이터를 읽기만 하므로 RNG가 필요 없습니다.

## store / 복구 정책

`JvckMetadataStore`는 `EncryptedOffsetStore`를 구현하며 모든 configured replica를 대상으로 동작합니다.

- `store()`: 모든 replica에 동일한 `encrypted_offset`을 기록.
- `load()`: HMAC 검증에 성공한 replica만 후보로 사용.
- **복구**: replica 간 `encrypted_offset`이 다르면(암호화 중 강제 종료 등) **가장 큰 값을 채택**합니다.
  더 큰 offset까지는 이미 암호화가 적용됐을 수 있으므로, 평문을 암호문으로 오인하지 않으려면 큰 값을
  택해야 합니다. 이후 채택값으로 모든 replica를 재동기화합니다.

## AES-256-XTS tweak 규약

데이터 영역 섹터는 `XtsVolumeCipher`(`lib/common/src/xts.rs`)로 암복호합니다. tweak = **데이터 영역 상대
섹터 번호**(`rel = lba - offset_sector`). 로더와 드라이버가 동일 구현을 쓰므로 부팅 윈도우 복호화와 런타임
복호화가 일치합니다. (섹터는 항상 16바이트 배수라 ciphertext stealing은 발생하지 않습니다.)

## Vendor ID 확장

기본 sample은 EncryptedMetadata=AES-256-CBC, 볼륨 암호화=AES-256-XTS를 선택합니다. **lib는 메타데이터
복호화도 볼륨 cipher도 정해 두지 않습니다** — sample이 볼륨별로 결정합니다.

- **sample이 직접 복호화 (정책 소유)**: lib는 attach 시 볼륨 데이터 경로 위의 owning `SectorIo`를 sample에
  넘깁니다.
  - 드라이버: `VolumeProvider::on_attach(&AttachContext)` — `ctx.io`(SectorIo) + `ctx.vmk`를 받아 sample이
    메타데이터를 읽고 **자기 알고리즘으로 복호화**한 뒤 `VolumeCipher`를 만들어
    `IoConfig::Encrypted { cipher, … }`로 반환. 기본 sample은 `JvckMetadataStore::open`(JVCK/AES-CBC) +
    `AesXtsCipher`를 씁니다. `DriverEntry`의 `set_volume_provider(&PROVIDER)`로 등록되어 부팅 OS 볼륨 mount와
    IOCTL attach 양쪽이 같은 경로를 탑니다.
  - 로더: sample이 `locate_block_io_volume` → `JvckMetadataStore::open`으로 직접 복호화하고 cipher를 만들어
    `BlockIoHookEngine::new(geometry, cipher)`로 넘깁니다.
- **metadata cipher도 교체 가능 (2단계 open)**: `JvckMetadataStore`는 metadata cipher(EncryptedMetadata
  봉인)를 하드코딩하지 않습니다. open이 2단계입니다.
  - **Phase A** — `JvckMetadataReader::open(io)`: **복호화 없이** plaintext 헤더/레이아웃만 파싱.
    `reader.header()`(`vendor_id`/`vendor_version`/192B `vendor_reserved` …)와
    `reader.read_vendor_data(replica, rel_sector, buf)`로 **복호화 전에** codec을 고를 수 있습니다.
  - **Phase B** — `reader.into_store(vmk, select)`: CRC 통과한 replica를 순회하며 각 replica마다
    `ReplicaCtx`를 만들어 **`select(&ctx)` 클로저**를 호출, `Ok((codec, unsealed))`를 돌려준 **첫 replica를
    채택**(아니면 다음 replica). `select`가 codec 선택 + unseal + 추가 검증을 모두 하고 **codec과 unsealed를
    함께 반환**합니다 — CRC가 맞아도 복호화 결과(예: replica 간 `encrypted_offset` 불일치)나 vendor specific
    data가 잘못됐을 수 있으므로, 그 replica를 `Err`로 건너뛸 수 있습니다. `ReplicaCtx`는 `header()` /
    `encrypted_metadata()` / `block()` / `salt()` / `read_vendor_data()`를 제공.
  - 반환된 codec(`MetadataCodec`)은 `unseal`(복호화) + `seal`(재봉인) **양방향**을 담당하며 store가 보관해
    sweep 중 `store`/`store_state` 재봉인과 `load_offset` 복구에 그대로 씁니다. into_store 자체는 codec을 받지
    않습니다 — selector가 replica를 보고 골라 돌려줍니다. 기본 suite는 `JvckCbcCodec`(AES-256-CBC + HKDF +
    HMAC), 벤더는 JVCK 컨테이너(replica·salt·HMAC)를 유지한 채 내부 cipher만 바꾼 codec을 돌려줍니다.
    `JvckMetadataStore::open(io, vmk)`은 기본 JVCK codec으로 두 단계를 잇는 convenience.
- **Vendor specific data 영역**: 각 replica는 Metadata 블록(1 섹터) 외에 `metadata_size - sector_size`
  만큼의 벤더 전용 영역을 가집니다. `JvckMetadataStore`가 섹터 단위 R/W API를 제공합니다:
  `replica_count()`, `vendor_data_sector_count()`, `read_vendor_data(replica, rel_sector, buf)`,
  `write_vendor_data(replica, rel_sector, buf)`. (버퍼는 sector_size의 배수, 범위는 replica 영역 내로 검증.)
- **저수준 경로**: 고수준 `VolumeCipher` 디스패치가 맞지 않으면, `IoConfig::Custom` + `IoHooks`로 섹터 I/O
  자체를 벤더가 직접 구동할 수도 있습니다.
