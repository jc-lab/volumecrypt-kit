<!--
SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>

SPDX-License-Identifier: Apache-2.0
-->

# 부팅 / 암호화 흐름

## 데이터 볼륨 (UEFI 무관)

OS 부팅 후 Go CLI로 최초 1회 `prepare`(메타데이터 기록 + attach) 후 `encrypt`로 sweep을 시작합니다.
신규 파티션이면 header replica를, 기존 파티션이면 footer replica만 사용합니다.
이후 재부팅 시에는 `attach`(mount)로 재연결하고 `detach`(dismount)로 해제합니다.

```
[vck-app data-volume prepare --volume \\.\D: --vmk <base64> --use-footer 2 ...]   # 최초 1회
   │  shrink(footer 공간 확보) + JVCK 메타데이터 생성·기록
   │  IOCTL_JVCK_PREPARE   (1단계: 필터 부착 + size hiding → NTFS가 메타데이터 영역에
   │                        VBR 백업을 쓰지 않도록 보호. 앱은 이후 메타데이터를 안전하게 기록)
   │  IOCTL_JVCK_ATTACH    (2단계: 볼륨에서 JVCK 메타데이터 읽기 → VMK로 FVEK·encrypted_offset
   │                        복원 → 볼륨 cipher 등록)
   ▼
[vck-app data-volume encrypt --volume \\.\D:]   # decrypt 로 역방향
   │  IOCTL_VCK_START_ENCRYPT → 드라이버가 per-volume 스레드에서 백그라운드 sweep 시작
   │  IOCTL_VCK_GET_PROGRESS (논블로킹 polling) → 진행률 스트림
   ▼
[encrypted_offset == total_sectors → StateIdle, 완료]

재부팅 후: [vck-app data-volume attach --volume \\.\D: --vmk <base64>]   # mount (메타데이터 읽기만)
해제:       [vck-app data-volume detach --volume \\.\D:]                  # dismount
```

복호화는 `data-volume decrypt`(= `IOCTL_VCK_START_DECRYPT`, 역방향 sweep). `detach`는 `IOCTL_VCK_DETACH`로
암호화 레이어 해제(dismount).

## OS(시스템) 볼륨 — 3부팅 흐름

OS 볼륨은 이미 파일시스템이 있으므로 footer에 메타데이터를 두고, 부팅 윈도우는 UEFI 로더가, 런타임은
커널 드라이버가 복호화합니다. `make test-vm-os-encrypt`가 이 전체 경로를 검증합니다.

### Boot 1 — 드라이버 설치
INF로 드라이버를 Volume 클래스 UpperFilter(boot-start)로 설치 → 재부팅. AddDevice가 NTFS 마운트 전에
각 볼륨 PDO에 unbound(pass-through) 필터를 부착합니다.

### Boot 2 — 최초 암호화 + 로더 설치
```
1. 파일시스템 shrink (footer 메타데이터 공간 확보; Go sdk.ShrinkVolumeTail)
2. IOCTL_JVCK_PREPARE → footer replica에 JVCK 메타데이터 기록(고정 VMK), 필터 바인딩
3. IOCTL_VCK_START_ENCRYPT → 백그라운드 sweep로 데이터 영역 암호화(진행 위치 영속화)
4. (EFI)/vck.json 생성, bootmgfw.efi → bootmgfw.os.efi 백업, 로더를 bootmgfw.efi로 설치 → 재부팅
```

### Boot 3 — 로더 경유 부팅 → 런타임 복호화
```
[펌웨어] → [sample/loader (구 bootmgfw.efi)]
  1. (EFI)/vck.json에서 VMK·다음 OS 로더 경로 읽기
  2. 대상 OS 볼륨을 EFI_BLOCK_IO로 열어 footer 메타데이터 읽기 → VMK로 복호화
     → FVEK·encrypted_offset·지오메트리 복원
  3. EFI_BLOCK_IO_PROTOCOL.ReadBlocks 후킹 → 부팅 윈도우 동안 데이터 영역 투명 복호화
  4. VckHandoverPayload{partition_guid, vmk}를 EfiRuntimeServicesData 메모리에 msgpack 직렬화
     → 그 버퍼의 물리 주소·길이를 담은 HandoverLocator(msgpack)를 UEFI 런타임 변수로 SetVariable 발행
     (페이로드 버퍼는 ExitBootServices 이후 OS까지 살아남도록 의도적으로 leak;
      로더 지역 VMK/FVEK 사본은 사용 후 zeroize)
  5. bootmgfw.os.efi 체인로드 → Windows Boot Manager 기동
        │
        ▼
[Windows 커널 부팅] sample/windrv DriverEntry
  1. ExGetFirmwareEnvironmentVariable로 locator 변수 읽기 → HandoverLocator 역직렬화
     → MmMapIoSpace로 페이로드 물리 버퍼 매핑 → 역직렬화
     VMK를 보호 메모리로 복사 후 매핑 버퍼(평문 VMK) zeroize·unmap
  2. 필터의 IRP_MN_START_DEVICE 완료 후(handover_mount): 하위 디바이스 GPT PartitionId를 handover와
     매칭 → footer 메타데이터를 VMK로 복호화 → FVEK·encrypted_offset·cipher 복원
     → AttachSource::Handover 볼륨으로 filter_bind_volume → sweep 재개(start_encrypt)
  3. 이후 모든 OS 볼륨 I/O를 per-volume 스레드가 런타임 복호화 (encrypted_offset 영속화 시 footer replica 갱신)
        │
        ▼
[Windows 정상 부팅 완료]  (마커 파일 무결성 검증)
```

> 부팅 윈도우(winload가 OS 볼륨을 읽는 구간)는 로더의 BlockIo 후킹이, OS 진입 이후는 커널 드라이버가
> 복호화를 담당합니다. 두 경로 모두 동일한 `XtsVolumeCipher`와 동일한 footer 메타데이터를 사용하므로
> 경계에서 불일치가 없습니다.

## 점진적 암호화 상태 머신

모든 비교는 데이터 영역 상대 섹터(`rel = lba - offset_sector`) 기준이며, 메타데이터 영역 I/O는
암복호 없이 통과합니다.

```
Read(lba):
  메타데이터 영역      → pass-through (평문)
  rel < encrypted_offset  → AES-XTS 복호화 후 반환
  rel >= encrypted_offset → 평문 그대로 반환

Write(lba):
  메타데이터 영역      → pass-through (평문)
  rel < encrypted_offset  → AES-XTS 암호화 후 하위로
  rel >= encrypted_offset → 평문 그대로 하위로

Sweep(배치):
  encrypted_offset 이후 1배치(기본 2048섹터=1MiB) 읽기 → 암호화 → 기록
  → encrypted_offset 전진 → offset_store.store()/flush()로 영속화
```

**graceful shutdown**: `IoRegisterShutdownNotification` 핸들러가 OS 볼륨은 `PAUSE_OS_VOLUME`으로
sweep만 멈추고(필터 유지 → 셧다운 중 쓰기도 암호화), 데이터 볼륨은 `DETACH_ALL_VOLUMES`로 정리합니다.

**알려진 한계**: 한 배치의 ciphertext를 기록한 뒤 `encrypted_offset`을 영속화하기 전에 전원이 끊기면,
재부팅 시 그 1배치를 다시 암호화하여 손상될 수 있습니다(double-encryption). 완전한 crash-consistency는
hotzone 저널링이 필요하며 샘플 범위 밖입니다(`offset/engine.rs`에 문서화).
