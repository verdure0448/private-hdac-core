## ubuntu에서 정적으로 빌드하기

정적으로 링크해서 빌드할 때는 depends 디렉토리에 있는 package를 이용한다.

ubuntu 16.04 환경에서 minimal로 설치되었다고 가정한 상태에서 다음과 같은 package가 필요하다.

```bash
sudo apt install autoconf
sudo apt install libtool
sudo apt install build-essential
sudo apt install pkg-config
```

build.sh를 실행해서, depends에 있는 package와 hdac-core를 한 번에 빌드할 수 있다.
```bash
./build.sh
```

## Trouble shootings

depends의 boost 가 빌드되지 않는 경우 c++14 를 이용해서 빌드를 성공했다. 

ubuntu 18.04 에서는 별 설정이 없이 성공했는데, gcc-7이 default standard로 c++14를 설정이 되기 때문인 것으로 판단한다.
ubuntu 16.04 는 gcc-5가 설치되어 있으며 default standard가 c++98 이다.

확인할 파일 및 부분은 다음과 같다.

### depends/packages/boost.mk
```makefile
...
$(package)_config_libraries=chrono,filesystem,program_options,system,thread,test
$(package)_cxxflags=-fvisibility=hidden
$(package)_cxxflags_linux=-fPIC
...
-->
...
$(package)_config_libraries=chrono,filesystem,program_options,system,thread,test
$(package)_cxxflags=-fvisibility=hidden
$(package)_cxxflags_linux=-fPIC -std=c++14
...

```

### configure.ac
```makefile
...
dnl Compiler checks (here before libtool).
if test "x${CXXFLAGS+set}" = "xset"; then
  CXXFLAGS_overridden=yes
else
  CXXFLAGS_overridden=no
fi
AC_PROG_CXX
m4_ifdef([AC_PROG_OBJCXX],[AC_PROG_OBJCXX])
...
-->
...
dnl Compiler checks (here before libtool).
if test "x${CXXFLAGS+set}" = "xset"; then
  CXXFLAGS_overridden=yes
else
  CXXFLAGS_overridden=no
fi
AC_PROG_CXX
m4_ifdef([AC_PROG_OBJCXX],[AC_PROG_OBJCXX])

AX_CHECK_COMPILE_FLAG([-std=c++14], [CXXFLAGS="$CXXFLAGS -std=c++14"], [notcomp14=1])
if test x$notcomp14 != x; then
        AX_CHECK_COMPILE_FLAG([-std=c++11], [CXXFLAGS="$CXXFLAGS -std=c++11"])
fi
...

```
