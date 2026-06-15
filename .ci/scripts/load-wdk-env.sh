#!/usr/bin/env bash

OLD_PATH="$PATH"

SETUP_CMD='G:\\BuildEnv\\SetupBuildEnv.cmd'

if [ -f "${SETUP_CMD}" ]; then
  while IFS='=' read -r name value; do
    upper_name="${name^^}"
    value="${value%$'\r'}"

    case "$upper_name" in
      PATH)
        # Windows Path list (; separated, C:\...) -> MSYS PATH list (: separated, /c/...)
        win_path_as_msys="$(cygpath -u -p "$value")"

        # MSYS 기존 PATH 보존
        export PATH="$win_path_as_msys:$OLD_PATH"
        ;;
      INCLUDE|LIB|LIBPATH|WDKCONTENTROOT|WINDOWSSDKDIR|WINDOWSSDKVERSION|VCTOOLSINSTALLDIR|VCINSTALLDIR)
        # 이 변수들은 MSVC/link/bindgen 같은 Windows tool이 볼 값이므로
        # Windows 형식과 ; separator를 유지하는 편이 맞습니다.
        export "$name=$value"
        ;;
    esac
  done < <(MSYS2_ARG_CONV_EXCL="/c" cmd.exe /c "call $SETUP_CMD && set")
fi
