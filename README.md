# Crypto Finance Development Kit for Go (CFD-GO)

<!-- TODO: Write Summary and Overview

## Overview

-->

## Dependencies

- Go (1.12 or higher)
- C/C++ Compiler
  - can compile c++11
  - make support compiler
- CMake (3.14.3 or higher)
- Python 3.x
- node.js (stable version)
  - for cmake-js

### Windows (MinGW)

attention: Cgo can only be used on the `make` platform.

(Recommended to use wsl(Windows Subsystem for Linux), because it can be cumbersome.)

- MinGW (http://mingw-w64.org/doku.php)
  - download and install files.
    - go (1.12 or higher)
    - MinGW (Add to PATH after install)

### MacOS

- [Homebrew](https://brew.sh/)

```Shell
# xcode cli tools
xcode-select --install

# install dependencies using Homebrew
brew install cmake go node
```

### Linux(Ubuntu)

```Shell
# install dependencies using APT package Manager
apt-get install -y build-essential golang cmake nodejs
```

cmake version 3.14.2 or lower, download from website and install cmake.
(https://cmake.org/download/)

go version 1.11 or lower, get `golang.org/dl/go1.12` or higher.
(https://www.mazn.net/blog/2019/02/03/1704.html)

---

## Build

### Using cmake-js

(If you want to install, [see the installation](#Using-cmake-js-install). Introduces build and install command.)

When using the cmake-js package and npm script, the options for compilation are already set.

```Shell
npm install
npm run cmake_release
go build
```

### Using CMake

```Shell
# recommend out of source build
mkdir build && cd $_
# configure & build
cmake .. -DENABLE_SHARED=on -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=off -DENABLE_JS_WRAPPER=off -DENABLE_CAPI=on -DTARGET_RPATH=/usr/local/lib/
make
cd ..
go build
```

**CMake options**

`cmake .. (CMake options) -DENABLE_JS_WRAPPER=off`

- `-DENABLE_ELEMENTS`: Enable functionalies for elements sidechain. [ON/OFF] (default:ON)
- `-DENABLE_SHARED`: Enable building a shared library. [ON/OFF] (default:OFF)
- `-DENABLE_TESTS`: Enable building a testing codes. If enables this option, builds testing framework submodules(google test) automatically. [ON/OFF] (default:ON)
- `-DCMAKE_BUILD_TYPE=Release`: Enable release build.
- `-DCMAKE_BUILD_TYPE=Debug`: Enable debug build.
- `-DCFDCORE_DEBUG=on`: Enable cfd debug mode and loggings log files. [ON/OFF] (default:OFF)

---

## install / uninstall

On Linux or MacOS, can use install / uninstall.

### install (after build)

install for `/usr/local/lib`.

#### Using cmake-js install

When using the cmake-js package and npm script, the options for compilation are already set.

Attention: Currently, there is a problem with ExternalProject, so a problem occurs when performing update processing. Please perform cleanup when building before installation.

```Shell
(cleanup)
./tools/cmake_cleanup.sh
sudo ./tools/cleanup_install_files.sh

(build and install by using makefile)
npm run cmake_make_install
(Enter the password when prompted to use the sudo command.)
```

cmake version is 3.15 or higher:
```Shell
(cleanup)
./tools/cmake_cleanup.sh
sudo ./tools/cleanup_install_files.sh

(build and install by using ninja or makefile)
npm run cmake_install
(Enter the password when prompted to use the sudo command.)
```

#### Using CMake install

Attention: Currently, there is a problem with ExternalProject, so a problem occurs when performing update processing. Please perform cleanup when building before installation.

```Shell
(cleanup)
./tools/cmake_cleanup.sh
sudo ./tools/cleanup_install_files.sh

(build)
mkdir build && cd build && cmake .. -DENABLE_SHARED=on -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=off -DENABLE_JS_WRAPPER=off -DENABLE_CAPI=on -DTARGET_RPATH=/usr/local/lib && make

(install by using makefile)
cd build && sudo make install

(install by using ninja)
cd build && sudo ninja install
```

cmake version is 3.15 or higher: `cmake --install build`

#### Using releases asset (ubuntu / macos)

```Shell
(cleanup)
./tools/cmake_cleanup.sh
sudo ./tools/cleanup_install_files.sh

(download)
wget https://github.com/p2pderivatives/cfd-go/releases/download/v0.1.0/cfdgo-v0.1.0-ubuntu1804-gcc-x86_64.zip

(unzip)
sudo unzip -q cfdgo-v0.1.0-ubuntu1804-gcc-x86_64.zip -d /
```

### uninstall
```Shell
(uninstall by using makefile)
cd build && sudo make uninstall

(uninstall by using ninja)
cd build && sudo ninja uninstall

(uninstall by using script)
sudo ./tools/cleanup_install_files.sh
```

---

## How to use cfd-go as go module

1. Once, clone this repository.
2. Build & install cfd-go(and dependencies).
3. Modify `go.mod` file adding cfd-go as go moudle

go.mod

```
require (
  github.com/p2pderivatives/cfd-go v0.1.0
  ...
)
```

Reference github commit:
```
require (
  github.com/p2pderivatives/cfd-go v1.0.0-0.20191205091101-a48a6a8b1a24
  ...
)
```
(version format: UnknownVersionTag-UtcDate-CommitHash)

4. Download cfd-go module

```Shell
go mod download
```

---

## Development information

### managed files

- cfdgo.go, cfdgo.cxx: generated from swig.
- swig.i: swig file.

#### generate from swig.i

attention: At first, install swig and set PATH.

```
(linux/macos)
./tools/gen_swig.sh

(Windows)
.\tools\gen_swig.bat
```

### Test

test file is `cfdgo_test.go` . Execute by the following method.

- shell script or bat file
```
(linux/macos)
./go_test.sh

(Windows)
.\go_test.bat
```

- go command
```Shell
LD_LIBRARY_PATH=./build/Release go test
```

### Example

- cfdgo_test.go

---

## Note

### Git connection:

Git repository connections default to HTTPS.
However, depending on the connection settings of GitHub, you may only be able to connect via SSH.
As a countermeasure, forcibly establish SSH connection by setting `CFD_CMAKE_GIT_SSH=1` in the environment variable.

- Windows: (On the command line. Or set from the system setting screen.)
```
set CFD_CMAKE_GIT_SSH=1
```

- MacOS & Linux(Ubuntu):
```
export CFD_CMAKE_GIT_SSH=1
```
