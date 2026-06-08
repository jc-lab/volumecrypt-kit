## 1. 코딩 전 생각하기

**추측하지 마세요. 모호한 부분을 숨기지 마세요. 장단점을 명확히 드러내세요.**

구현 전:
- 가정을 명확하게 명시하세요. 불확실하면 질문하세요.
- 여러 가지 해석이 가능하다면, 모두 제시하세요. 묵묵히 선택하지 마세요.
- 더 간단한 방법이 있다면, 그렇게 말하세요. 필요하다면 반대 의견을 제시하세요.
- 불분명한 부분이 있다면, 멈추세요. 무엇이 헷갈리는지 파악하고 질문하세요.

## 2. 코드 규칙

- 주석은 영어로만 작성하세요.

## 3. 환경

- msys64 가 `c:\msys64` 에 설치되어 있습니다. 이를 기본 쉘로 사용하세요.
- `export PATH=/d/programs:$PATH` 가 필요합니다.
- WEDK 는 `G:\` 에 마운트 되어 있습니다. 다음을 참고하세요:

```
invoke_driver_build() {
  pushd "$src_dir"X
  MSYS2_ARG_CONV_EXCL="/c" cmd.exe /c 'call G:\BuildEnv\SetupBuildEnv.cmd && cargo build -p ... --target x86_64-pc-windows-msvc'
  popd
}
```

## 4. 테스트

- `test-foundry.exe` 을 통해 VM 안에서 테스트가 가능합니다. 이 툴에 대해서는 https://github.com/jc-lab/test-foundry 을 참고하세요.
- 제가 이미 `test-foundry.exe --vm-name="win11" vm-setup --image ./testing/images/windows-11.yaml` 으로 vm setup 을 완료했습니다. 다시 setup 하지 말고 test 명령만 사용하세요.
- 이를 통해 VM 안에서 드라이버 로드, EFI 파일 변경 등의 모든 작업이 가능합니다.
- 실제 VM 안에서 테스트가 필요한 경우 test recipe 을 작성하고 Makefile 에서 테스트 할 수 있게 하세요.
- VM 안에 10GB 용량의 `D:\` 파티션도 존재합니다.

## 5. 구현

- 구현 시 TODO.md 을 참고하고, 구현을 완료할 때마다 TODO.md 을 업데이트하세요.
- 빌드/테스트에 Makefile 을 사용하세요.

## 6. 구조(아키텍쳐) 변경

- 중간에 아키텍쳐 변경 시 ARCH.md 와 TODO.md 에서 관련 부분 또한 수정해야 합니다.
