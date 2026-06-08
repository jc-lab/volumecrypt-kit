# volumecrypt-kit TODO

`ARCH.md`를 기준으로 한 구현 작업 목록입니다. 아키텍처가 바뀌면 `ARCH.md`와 이 파일을 함께 갱신하세요(AGENTS.md §6).

현재 상태: **JVCK 암호 코어 구현 완료**(호스트 단위테스트 20개 통과). 커널/UEFI 배선은 대부분 스텁입니다.
아래 각 항목은 채워야 할 구체적인 파일·함수를 가리킵니다.

> 빌드 참고: `lib/driver`는 호스트(`cargo build -p vck-driver --target x86_64-pc-windows-msvc`)에서
> `debug.rs`의 `wdk_sys::ntddk` import만 미해결(WDK 바인딩은 WEDK `G:\` 환경에서 생성됨)이고 나머지
> 모듈은 타입체크를 통과합니다. 따라서 드라이버 추가 작업은 `make build-driver`(WEDK)로 검증하세요.

## 빌드 / 테스트 명령 (Makefile)

| 명령 | 대상 | 환경 |
|---|---|---|
| `make build-common` / `make test` | `vck-common` 빌드 / 호스트 단위테스트 | 호스트(msvc) — **현재 통과** |
| `make build-driver` | `vck-sample-driver` → `vck-sample-driver.sys` | WEDK(G:\), `x86_64-pc-windows-msvc` |
| `make build-crypto-test-driver` | `vck-crypto-test-driver` → `.sys` | WEDK |
| `make build-loader` | `vck-sample-loader` | `x86_64-unknown-uefi` |
| `make build-app` | `vck-app.exe` (Go) | 호스트 — **현재 통과** |
| `make test-vm-driver-load` / `test-vm-crypto-test` | test-foundry VM | win11 VM |

> 커널/UEFI 크레이트는 호스트에서 빌드되지 않습니다(wdk-sys / uefi 타깃). 순수 로직은 `vck-common`
> (std)에서 `cargo test`로 검증하고, 커널 동작은 `vck-crypto-test-driver`로 VM에서 검증합니다.

---

## 0. 선행 작업 (cross-cutting, 다른 작업의 전제)

- [ ] **커널 global allocator**: `sample/driver/src/lib.rs`, `sample/crypto-test/src/lib.rs`에
  `#[global_allocator]` 설정 필요(예: `wdk-alloc::WdkAllocator`). `Cargo.toml`에 `wdk-alloc` 의존성 추가 +
  `Cargo.lock` 갱신. (현재 `// TODO(...) global allocator` 주석만 있음)
- [x] ~~**AES-XTS tweak 규약 확정**~~ — 해결: `lib/common/src/xts.rs::XtsVolumeCipher`로 단일화.
  tweak = **데이터영역 상대 섹터(`rel = lba - offset_sector`)**. loader/driver 모두 이 cipher 사용.
  (`lib/driver/src/crypto/aes_xts.rs`가 위임, 호스트 라운드트립 테스트 통과)
- [x] ~~**`IoHooks` 객체 안전성**~~ — 해결: `IoHooks`를 동기 시그니처로 변경하여 `Arc<dyn IoHooks>` object-safe.
- [ ] **GUID 엔디안 변환**: `lib/common/src/types.rs::Guid`(= `uuid::Uuid`) ↔ GPT/`EFI_GUID` 혼합
  엔디안 변환 헬퍼 추가(파티션 매칭용).
- [ ] **vck.json 파서 결정**: `sample/common/src/config.rs::VckConfig::parse_json`은 `no_std` JSON 파서 필요
  (serde_json은 std). 파서 선택 또는 config 포맷을 `no_std` 친화 포맷으로 변경.
- [ ] **loader BootServices 시그니처 정리**: uefi 0.37은 boot services를 전역 함수(`uefi::boot::*`)로 제공.
  `lib/loader/src/provider.rs::LoaderProvider::on_init(&BootServices)`,
  `sample/loader`의 `JvckMetadataStore::open_volume_footer_uefi(boot_services, ...)` 호출,
  `VckConfig::load_from_esp(boot_services)`에서 `boot_services` 인자를 제거하고 전역 API로 통일.
  (`lib/common`의 `open_volume_footer_uefi(partition_guid, vmk)` / `load_from_esp()`가 정답 시그니처)
- [ ] **`DevicePath` 타입 확정**: `lib/loader` `LoaderConfig::next_loader`와
  `sample/common::VckConfig::osloader_device_path` 반환형을 `uefi::proto::device_path::DevicePathBuffer`로 일치.

---

## 1. JVCK 암호 프리미티브 — `lib/common` (✅ 완료, 호스트 테스트 20개 통과)

- [x] `lib/common/src/jvck/metadata.rs` — `derive_keys`(HKDF-SHA256), `JvckMetadata::parse`
  (signature→CRC32→HMAC→AES-256-CBC 복호화→내부 검증), `encode`(역), `verify_crc`.
- [x] `lib/common/src/xts.rs` — `XtsVolumeCipher`(공유 AES-256-XTS, 섹터/영역 단위).
- [x] `lib/common/src/jvck/store.rs` — `JvckMetadataStore::open`/`create`/`load_metadata`,
  `EncryptedOffsetStore` 구현(복구 정책=최대 `encrypted_offset`), header/footer replica 레이아웃
  (footer는 마지막 섹터에 Metadata). in-memory `MemVolume`로 단위테스트.
- [x] 단위테스트: metadata round-trip, CRC/HMAC/서명 실패, HKDF 결정성/라벨분리, geometry,
  store/load/reopen, 복구 정책, XTS round-trip/tweak 의존성.
- [ ] (uefi feature) `UefiBlockIoVolume`의 `SectorIo` 4개 메서드 + `open_volume_footer_uefi`
  — 여전히 스텁(WEDK/UEFI 환경 필요).

---

## 2. 커널 드라이버 프레임워크 — `lib/driver`

> 아래 [x] 항목은 호스트 타입체크 통과(로직 구현). 나머지는 ntddk/IRP API가 필요해 WEDK에서 구현.

- [x] `lib/driver/src/crypto/aes_xts.rs::AesXtsCipher` — `vck_common::XtsVolumeCipher`에 위임.
- [x] `lib/driver/src/crypto/pipeline.rs::CryptoPipeline` — `decrypt_read`/`encrypt_write`
  (상대 섹터 공간, `encrypted_offset` 경계 기준 섹터별 분기).
- [x] `lib/driver/src/offset/engine.rs::EncryptionEngine` — `relative`(헤더/푸터 모두 제외 확인),
  `start_encrypt`/`start_decrypt`/`pause`, `progress_step`(암/복호 배치 + store 영속화), `snapshot`.
- [ ] `lib/driver/src/io.rs::KernelVolumeIo` — `read_sectors`/`write_sectors`
  (하위 디바이스에 동기 IRP_MJ_READ/WRITE). `open`은 골격 완료. **하위(lower) 디바이스 핸들 필요.**
- [ ] `lib/driver/src/filter/manager.rs::VolumeFilterDriver` — `attach`(filter DO 생성 +
  `IoAttachDeviceToDeviceStackSafe`) / `detach`.
- [ ] `lib/driver/src/filter/irp.rs` — `on_read`/`on_write`/`pass_through`
  (IRP 완료 콜백 → `CryptoPipeline`).
- [ ] `lib/driver/src/executor.rs::KernelExecutor` — `spawn`/`block_on`
  (IRP completion waker + `ExWorkItem` 워커).
- [ ] `lib/driver/src/ioctl/dispatch.rs` — `handle_get_status`/`start_encrypt`/`start_decrypt`/
  `get_progress`(논블로킹)/`pause`/`jvck_attach`/`detach`. msgpack 디코드/인코드는
  `ioctl/types.rs` 구조체 사용.
- [ ] `lib/driver/src/device.rs::ControlDevice` — `create`(`IoCreateDevice` + `IoCreateSymbolicLink`,
  `DEVICE_NAME`/`SYMLINK_NAME`) / `destroy`.
- [ ] `lib/driver/src/handover.rs::read_handover::<P>()` — ACPI 테이블 영역 획득 후
  `AcpiHandoverReader::find_and_decode`. 성공 시 VMK 보호 메모리 복사 + ACPI 버퍼 zeroize.
- [ ] `lib/driver/src/provider.rs` — `AccessToken` 실제 토큰 래핑.

> 검증 불변식: `ioctl/codes.rs`의 IOCTL 값과 `ioctl/types.rs`의 필드/태그는
> `sdk/ioctl.go`·`sdk/types.go`와 **반드시 동일**해야 함.

---

## 3. UEFI 로더 — `lib/loader` + `sample/loader`

- [ ] `lib/loader/src/hook/mod.rs::BlockIoHookEngine` — `install`/`uninstall`/`decrypt_after_read`
  (대상 파티션 GUID 매칭, 원본 ReadBlocks/Ex 포인터 저장 후 vtable 교체).
- [ ] `lib/loader/src/hook/block_io.rs` / `block_io2.rs` — `EFI_BLOCK_IO(2)_PROTOCOL` 후킹 본문.
  훅 read: metadata 영역 passthrough → `rel = lba - offset_sector` → `rel < encrypted_offset`면
  원본 read 후 AES-XTS 복호화.
- [ ] `lib/loader/src/handover.rs::install_handover` — `AcpiHandoverWriter`로 VCKD 테이블 설치.
- [ ] `lib/loader/src/chainload.rs::chainload_next` — `LoadImage`/`StartImage`로 다음 OS 로더 기동.
- [ ] `sample/loader/src/provider.rs::VckLoaderProvider::on_init` — 골격은 ARCH 그대로(스텁).
  cross-crate 호출(`VckConfig::load_from_esp`, `open_volume_footer_uefi`, `osloader_device_path`)이
  실제로 동작하도록 §0의 시그니처 정리 반영.
- [ ] `sample/loader/src/main.rs::efi_main` — 패닉 핸들러/얼로케이터 wiring, `VckLoaderProvider` 구동.

---

## 4. 샘플 드라이버 — `sample/driver`

- [ ] `sample/driver/src/lib.rs::DriverEntry` — 컨트롤 디바이스 생성 → `read_handover` →
  PnP 알림 등록(OS 볼륨 도착 시 `on_attach`) → `IRP_MJ_DEVICE_CONTROL` → `ioctl::dispatch`.
- [ ] `sample/driver/src/provider.rs::require_administrator` — 요청자 토큰의
  BUILTIN\Administrators 멤버십 검사. (`on_attach`/`authorize` 골격은 완료, 내부 store 호출은 §1·§2 의존)

---

## 5. 인커널 암호 테스트 드라이버 — `sample/crypto-test`

- [ ] `sample/crypto-test/src/tests.rs` — `check_hkdf_derivation` / `check_header_crc32` /
  `check_encrypted_metadata_roundtrip` / `check_aes_xts_sector_roundtrip` 구현
  (각각 §1·§2 프리미티브 호출). 현재 모두 `false` 반환.
- [ ] `sample/crypto-test/src/lib.rs::DriverEntry` — `run_all()` 결과 → NTSTATUS 매핑
  (`STATUS_SUCCESS`/`STATUS_UNSUCCESSFUL`), 정리 후 언로드.

---

## 6. Go SDK / CLI — `sdk`, `sample/app` (대체로 완료)

빌드·`go vet` 통과. 남은 항목:

- [ ] `sample/app/cmd/attach.go` — base64 VMK 디코딩/검증 보강(현재 TODO 주석).
- [ ] `sample/app/cmd/status.go` — `EncryptionState`에 `String()` 추가하여 상태명 출력(현재 정수 출력).
- [ ] (선택) `sdk`에 비-windows 빌드 스텁 추가 여부 결정(현재 `//go:build windows`).

> 정의된 심볼: `Client`(`Open`/`Close`/`Attach`/`Detach`/`GetStatus`/`StartEncrypt`/`StartDecrypt`/
> `Pause`/`WatchProgress`), `deviceControl[Req,Resp]`, IOCTL 상수(`ioctlJvckAttach` 등),
> `JvckVolumeAttachRequest`/`Response`, `VolumeStatus`, `ProgressEvent`, `EncryptionState`,
> 비공개 `volumeRequest`.

---

## 7. 통합 / 테스트 자산

- [ ] test recipe 작성(Makefile이 참조하지만 부재):
  `testing/recipes/crypto-test/crypto-test.yaml`, `testing/recipes/smoke-guest-exec/smoke.yaml`.
  (`testing/recipes/driver-load/`는 존재)
- [ ] `testing/images/make-volume-d.ps1`로 만든 `D:\`(10GB)에서 Data Volume attach→encrypt→상태
  end-to-end 시나리오 recipe(`test-vm-data-volume`).
- [ ] OS Volume 최초 암호화의 파일시스템 Shrink 단계(`sample/app`에서 Windows VDS/diskpart 호출) 설계·구현.

---

## 권장 구현 순서

1. **§1** JVCK 프리미티브(호스트 `cargo test`로 즉시 검증) → 2. **§5** crypto-test 드라이버로 인커널 동치 검증
3. **§2** 드라이버 프레임워크 → 4. **§4** 샘플 드라이버 + `test-vm-driver-load`/`test-vm-data-volume`
5. **§3** UEFI 로더 → 6. **§7** OS Volume 부팅 end-to-end.
§0 항목은 각 단계 진입 전 전제로 처리하세요.
