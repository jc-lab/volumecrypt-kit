# volumecrypt-kit TODO

`ARCH.md`를 기준으로 한 구현 작업 목록입니다. 아키텍처가 바뀌면 `ARCH.md`와 이 파일을 함께 갱신하세요(AGENTS.md §6).

현재 상태: **JVCK 암호 코어 구현 완료**(호스트 단위테스트 20개 통과). 커널/UEFI 배선은 대부분 스텁입니다.
아래 각 항목은 채워야 할 구체적인 파일·함수를 가리킵니다.

> 빌드 참고:
> - `wdk-sys` 바인딩은 **다운스트림 드라이버 크레이트의 `[package.metadata.wdk]`** 기반으로 생성되므로,
>   `cargo build -p vck-driver` 단독은 빈 바인딩이 됩니다. 드라이버 컴파일 검증은 반드시 드라이버 바이너리
>   크레이트(`vck-sample-driver`/`vck-crypto-test-driver`)를 통해, **msys2 로그인 셸 + WEDK**에서:
>   `C:/msys64/usr/bin/bash.exe -lc 'cd /d/workspace/volumecrypt-kit; make build-driver'`.
> - `make build-driver`/`make build-crypto-test-driver`는 **빌드+서명까지 통과**합니다(현재 검증됨).
>   서명 스크립트(`testing/signing/sign-driver.ps1`)는 x64 signtool 우선 선택 + `Start-Process .ExitCode`
>   사용으로 셸 경계(`$LASTEXITCODE`) 문제를 회피합니다.
> - **panic 전략(혼합 워크스페이스)**: `panic="abort"`는 워크스페이스 `Cargo.toml`의 `[profile.dev]`/
>   `[profile.release]`에만 둡니다(전역 `.cargo/config.toml` 사용 안 함). cargo가 `test`/`bench` profile에서는
>   `panic=abort`를 무시하고 unwind를 쓰므로 `make test`(=`cargo test -p vck-common`)가 그대로 동작합니다.
>   드라이버 전용 플래그(`crt-static`, `aes_force_soft`)는 Makefile의 인라인 RUSTFLAGS로, `driver_model` cfg는
>   각 드라이버 크레이트의 `build.rs`(`wdk_build::configure_wdk_binary_build`)가 방출합니다.

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

- [x] **커널 global allocator**: `sample/driver/src/lib.rs`, `sample/crypto-test/src/lib.rs`에
  `#[global_allocator]` 설정 완료(`wdk-alloc::WdkAllocator`). 각 드라이버 crate에
  `wdk-build`/`wdk-alloc` 의존성과 `package.metadata.wdk.driver-model = "WDM"` 추가,
  `.cargo/config.toml`/`Makefile` WEDK 빌드 경로 정리. `make build-driver`,
  `make build-crypto-test-driver` 서명까지 통과.
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
- [x] `lib/driver/src/io.rs::KernelVolumeIo` — `read_sectors`/`write_sectors` 구현 완료
  (`IoBuildSynchronousFsdRequest` + `IofCallDriver` + `KeWaitForSingleObject` 동기 IRP).
  `open`(NT 경로→`IoGetDeviceObjectPointer`) 및 `from_lower_device`(필터 하위 디바이스) 제공.
  공용 NT 헬퍼는 `lib/driver/src/nt.rs`로 추출. `make build-driver`로 컴파일·링크·서명 검증.
  남은 것: 볼륨 geometry(sector_size/total_sectors) 질의 헬퍼(`IOCTL_DISK_GET_LENGTH_INFO` 등).
- [x] `lib/driver/src/filter/manager.rs` — `attach_filter`(filter DO 생성 +
  `IoAttachDeviceToDeviceStackSafe`, 확장 태깅, flag 상속) / `detach_filter`(IoDetachDevice +
  IoDeleteDevice + Arc 해제) 구현 완료.
- [x] `lib/driver/src/device.rs` — `DeviceExtension`(Control/Filter 태깅) 추가, 컨트롤 디바이스에 부착.
  sample 드라이버의 `dispatch_any`가 확장 kind로 IRP 라우팅(필터=pass-through, 컨트롤=IOCTL).
  ATTACH가 `attach_filter`까지, DETACH가 `detach_filter`까지 배선. **현재는 transparent pass-through**
  (볼륨 정상 동작 확인용). sweep_io는 필터 attach 전에 볼륨 디바이스를 해석해 재진입 없음.
- [ ] `lib/driver/src/filter/irp.rs` — READ/WRITE **crypto 가로채기** 미구현(현재 pass-through).
  read 완료 콜백에서 복호화, write는 shadow 버퍼 암호화 후 하위 전달. (다음 단계)
  PnP remove 처리(IRP_MN_REMOVE_DEVICE 시 자동 detach)도 보강 필요.
- [ ] `lib/driver/src/executor.rs::KernelExecutor` — `spawn`/`block_on`
  (IRP completion waker + `ExWorkItem` 워커).
- [x] `lib/driver/src/ioctl/dispatch.rs` — `handle_jvck_attach`/`handle_detach` 구현 완료.
  attach: NT 경로 변환 → `KernelVolumeIo::open_query`(geometry) → `JvckMetadataStore::open`(기존)
  또는 `create`(최초, 앱이 보낸 FVEK/volume_id 사용) → `AttachedVolume` 등록 → 응답.
  detach: registry 제거. (프로토콜: `JvckVolumeAttachReq`에 `fvek_key1/fvek_key2/volume_id` 추가,
  Go `JvckVolumeAttachRequest` + `attach.go`가 `crypto/rand`로 생성·전달.)
- [x] **암호화 sweep worker** ([sweep.rs](lib/driver/src/sweep.rs)) 구현 완료 —
  `PsCreateSystemThread` 기반 단일 시스템 스레드가 registry를 폴링하며 Encrypting/Decrypting 볼륨의
  `AttachedVolume::sweep_step`(→`EncryptionEngine::progress_step`)을 배치(1MiB)로 구동, offset 영속화.
  `START_ENCRYPT`/`DECRYPT`는 상태만 바꾸고 폴러가 자동으로 처리. DriverEntry에서 start, DriverUnload에서 stop(join).
  `SectorIo`에 `Send+Sync` 슈퍼트레이트 추가(`Arc<dyn SectorIo>` 스레드 공유용).
  주의: 아직 transparent 필터가 없어 sweep는 raw 볼륨을 직접 암호화하므로, 마운트된 FS와 충돌하지 않도록
  암호화 전 볼륨 lock/dismount가 필요(앱 책임). 실제 활용은 (2) 필터 attach 후 가능.
  **남은 것**: (2) transparent 볼륨 필터(아래).
- [x] `lib/driver/src/device.rs::ControlDevice` — `create`(`IoCreateDevice` + `IoCreateSymbolicLink`,
  `DEVICE_NAME`/`SYMLINK_NAME`) / `destroy` 구현 완료. `DO_BUFFERED_IO` 설정 및 unload 시 삭제 경로 포함.
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

- [ ] `sample/driver/src/lib.rs::DriverEntry` — 최소 제어 경로는 구현 완료:
  컨트롤 디바이스 생성/언로드, `IRP_MJ_CREATE`/`CLOSE`/`CLEANUP`, `IRP_MJ_DEVICE_CONTROL`
  → `ioctl::dispatch` 배선. 남은 작업은 `read_handover`, PnP 알림 등록(OS 볼륨 도착 시 `on_attach`),
  attach registry 실제 채우기. `make test-vm-driver-load` 현재 통과.
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
- [ ] `sample/app` OS Volume 최초 암호화 준비 — app에서 filesystem shrink, EFI `bootmgfw.os.efi`
  복사, `(EFI)/vck.json` 생성까지 구현 완료. 현재는 `os-volume encrypt --prepare-only`와
  VM recipe(`make test-vm-os-volume-prepare`)로 검증 가능. 실제 암호화 시작은 커널의
  OS Volume attach/handover 경로 구현 후 자동 연결됨.

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
- [ ] OS Volume 최초 암호화의 파일시스템 shrink 고도화:
  현재 `sdk.ShrinkVolumeTail()`에서 `FSCTL_SHRINK_VOLUME`와 필요 시 `FSCTL_MOVE_FILE`
  기반 tail cluster relocation을 수행한다. 실제 시스템 파일/고정 파일이 많은 경우의
  예외 경로와 재시도 정책은 계속 보강 필요.

---

## 권장 구현 순서

1. **§1** JVCK 프리미티브(호스트 `cargo test`로 즉시 검증) → 2. **§5** crypto-test 드라이버로 인커널 동치 검증
3. **§2** 드라이버 프레임워크 → 4. **§4** 샘플 드라이버 + `test-vm-driver-load`/`test-vm-data-volume`
5. **§3** UEFI 로더 → 6. **§7** OS Volume 부팅 end-to-end.
§0 항목은 각 단계 진입 전 전제로 처리하세요.
