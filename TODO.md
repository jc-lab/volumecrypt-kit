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
| `make build-loader` | `vck-sample-loader` → `.efi` | `x86_64-unknown-uefi` (RUSTFLAGS `--cfg aes_force_soft`) — **현재 통과** |
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
- [x] **GUID 엔디안 변환**: `lib/common/src/types.rs::guid_from_windows_bytes(b: [u8;16])` 추가
  (Windows/GPT `PartitionId`·`EFI_GUID`의 메모리 바이트 → `Uuid::from_bytes_le`로 canonical `Guid`).
  드라이버가 `IOCTL_DISK_GET_PARTITION_INFO_EX`로 읽은 GPT `PartitionId`를 handover/`vck.json`의
  canonical GUID와 매칭하는 데 사용. 호스트 단위테스트(`guid_from_windows_bytes_matches_canonical`) 통과.
- [x] **vck.json 파서 결정**: `sample/common/src/config.rs`에 `no_std` 평면 JSON 객체 스캐너(문자열 값만) +
  base64 디코더를 직접 구현. `parse_json`이 `partition_guid`(canonical GUID)/`vmk`(base64)/`osloader`
  (기본값 `DEFAULT_OSLOADER`)를 파싱. 호스트 단위테스트 5개 통과.
- [x] **loader BootServices 시그니처 정리**: uefi 0.37 전역 함수(`uefi::boot::*`)로 통일. `BootServices`
  alias 제거, `LoaderProvider::on_init(&self)`, `VckConfig::load_from_esp()`,
  `open_volume_footer_uefi(partition_guid, vmk)`, `osloader_device_path(&self)` 모두 인자 없는 형태로 일치.
- [x] **`DevicePath` 타입 확정**: uefi 0.37엔 `DevicePathBuffer`가 없음 → 소유형은
  `Box<uefi::proto::device_path::DevicePath>`(`DevicePath::to_boxed`). `LoaderConfig::next_loader`와
  `VckConfig::osloader_device_path` 반환형을 이로 일치.

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
- [x] `lib/driver/src/handover.rs::read_handover::<P>()` — `ZwQuerySystemInformation`
  (SystemFirmwareTableInformation, provider `ACPI`, tableID `VCKD`)로 테이블 조회 후
  `AcpiHandoverReader::decode`. plaintext VMK를 담은 커널 풀 버퍼는 owned `Vec`로 복사 후 zeroize+free.
- [x] **OS 볼륨 부팅 auto-attach (Stage 2b)** — `lib/driver/src/filter/handover_mount.rs`:
  `add_device`는 unbound 필터만 부착(기존), 실제 mount는 `IRP_MN_START_DEVICE` **완료 후**로
  지연(필터가 START를 가로채 completion routine 설치 → PASSIVE면 직접, 아니면 `IoWorkItem`으로 위임 후 대기).
  mount = 하위 디바이스 GPT `PartitionId`를 handover와 매칭 → `LowerDeviceIo`로 footer를 VMK
  복호화(`JvckMetadataStore`) → FVEK/offset/cipher 파생 → `AttachSource::Handover` 볼륨 빌드 →
  `filter_bind_volume`. handover 부재(로더 없음)면 no-op. `VolumeAttachRegistry`에 `HandoverInfo` 저장 +
  `set_global_registry`(work item C 콜백용) 추가. `make build-driver` 통과. 실제 handover 경로 end-to-end는
  Stage 3(로더) 통합 시 검증.
- [ ] `lib/driver/src/provider.rs` — `AccessToken` 실제 토큰 래핑.

> 검증 불변식: `ioctl/codes.rs`의 IOCTL 값과 `ioctl/types.rs`의 필드/태그는
> `sdk/ioctl.go`·`sdk/types.go`와 **반드시 동일**해야 함.

---

## 3. UEFI 로더 — `lib/loader` + `sample/loader`

- [x] `lib/loader/src/hook/mod.rs::BlockIoHookEngine` — `new`(AES-XTS cipher 구축)/`install`(대상 파티션
  GPT GUID 매칭 → 원본 `read_blocks` 저장 + 인스턴스 필드 패치)/`uninstall`(복원)/`decrypt_after_read`
  (섹터별 결정: header/footer passthrough, `rel < encrypted_offset.sector`면 AES-XTS 복호화) 구현.
- [x] `lib/loader/src/hook/block_io.rs` — `EFI_BLOCK_IO_PROTOCOL.read_blocks` 후킹 본문 + 전역 side table
  (protocol ptr→original/engine) + `efiapi` `hooked_read_blocks`(원본 read 후 `decrypt_after_read`).
  **컴파일만 검증; 실제 부팅 미검증(3h).**
  > `block_io2.rs`(EFI_BLOCK_IO2, async ReadBlocksEx)는 미후킹: Windows 부팅은 동기 BlockIo/
  > SimpleFileSystem 경로로 OS 볼륨을 읽음. 필요 시 후속 보강.
- [x] `lib/loader/src/handover.rs::install_handover` — **UEFI 런타임 변수**(`VckHandover`,
  `vck_common::handover::HANDOVER_VAR_{NAME,GUID}`)에 msgpack payload를 `SetVariable`
  (`BOOTSERVICE_ACCESS|RUNTIME_ACCESS`)로 발행. 드라이버는 `ExGetFirmwareEnvironmentVariable`로 읽음.
  > **전환 사유:** 커널 `ZwQuerySystemInformation(SystemFirmwareTableInformation, "ACPI")`가
  > Windows에서 `STATUS_NOT_IMPLEMENTED`(0xC0000002) 반환 → ACPI XSDT 주입 방식은 드라이버가 못 읽음.
  > XSDT 주입 코드(`AcpiHandoverWriter::install_uefi`)는 남아있으나 미사용. **VM 부팅 검증 완료(3h).**
- [x] `lib/loader/src/chainload.rs::chainload_next` — `uefi::boot::load_image(FromDevicePath)` +
  `start_image`로 다음 OS 로더 기동.
- [x] `sample/loader/src/provider.rs::VckLoaderProvider::on_init` — §0 시그니처 정리 반영, cross-crate
  호출 실제 동작(`VckConfig::load_from_esp`, `open_volume_footer_uefi`, `osloader_device_path`).
- [x] `sample/loader/src/main.rs::efi_main` — uefi feature(`global_allocator`/`panic_handler`/`logger`)로
  얼로케이터·패닉·로거 wiring, `vck_loader::run(&provider)` 구동.
- [x] **Stage 3h (handover 검증 완료)**: `make test-vm-os-handover`(recipe
  `testing/recipes/os-handover/os-handover.yaml`) — prepare→로더를 bootmgfw.efi로 설치→**로더 경유 재부팅**
  →드라이버 로드. **13/13 통과.** debug.log(0xe9)로 확인: 로더 실행→체인로드→Windows 부팅→드라이버
  `read_handover`가 UEFI 변수 읽어 partition GUID 복원. 로더는 0xe9 debugcon으로도 로그
  (`lib/loader/src/debug.rs`). **참고: test-foundry는 `--headless` 필수**(없으면 wait-boot 타임아웃).
- [x] **암호화 경로 검증 완료**: `make test-vm-os-encrypt`(`testing/recipes/os-encrypt`) **21/21 통과**.
  드라이버 INF 설치(Volume UpperFilter, boot-start)→재부팅→`os-volume encrypt --no-wait`(shrink+
  IOCTL_JVCK_PREPARE footer 쓰기+StartEncrypt)→부분 암호화(~2.7GB)→로더 설치→로더 경유 재부팅.
  Boot3에서 로더 `crypto=Some` BlockIo 후킹이 부팅 윈도우 복호화 + 드라이버가 handover로 C:
  재바인딩해 런타임 복호화 → Windows 정상 부팅 + 마커 파일 무결성. (app 배선 step29, handover_mount
  geometry IOCTL 버그 수정 step32 — `LowerDeviceIo`에 IRP `IoBuildDeviceIoControlRequest` 추가.)
- [x] **재부팅 sweep race 정밀 검증 + 완화(step33/34)**: (a) 재부팅 후 sweep 재개 —
  handover_mount가 start_encrypt 호출(엔진 Idle로 생성되던 문제). (b) graceful shutdown —
  `IoRegisterShutdownNotification` 등록(기존엔 IRP_MJ_SHUTDOWN이 안 왔음) + 핸들러를
  detach→`pause_all_volumes`로 변경(detach 시 OS 볼륨 평문 쓰기 손상 버그 수정; 필터 유지).
  `make test-vm-os-encrypt` 21/21, debug.log "IRP_MJ_SHUTDOWN — pausing sweeps" 확인.
- [ ] (잔여 한계) hard-crash(전원 차단) 시 배치 ciphertext 기록↔boundary 영속화 사이 1배치 손상 창:
  완전 crash-consistency는 hotzone 저널링 필요(샘플 범위 밖, engine.rs에 문서화). 전체 암호화
  소프트AES 속도(현재 부분 암호화로만 검증).

---

## 4. 샘플 드라이버 — `sample/driver`

- [x] `sample/driver/src/lib.rs::DriverEntry` — 제어 경로 + OS 볼륨 부팅 경로 배선 완료:
  컨트롤 디바이스 생성/언로드, `IRP_MJ_CREATE`/`CLOSE`/`CLEANUP`, `IRP_MJ_DEVICE_CONTROL`
  → `ioctl::dispatch`, `AddDevice`(unbound 필터 부착), `set_global_registry`,
  `read_handover::<VckHandoverPayload>()` best-effort → `REGISTRY.set_handover`. OS 볼륨 자동
  attach는 필터의 START_DEVICE 완료 경로(`handover_mount`)가 처리. `make test-vm-driver-load` 통과.
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
