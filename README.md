# Crypto Finance Development Kit for Go (CFD-GO)

<!-- TODO: Write Summary and Overview

## Overview

-->

## Dependencies

- Go (1.12 or higher)
- C/C++ Compiler
  - can compilefe c++11
  - make support compiler
- CMake (3.14.3 or higher)
- Python 3.x
- node.js (stable version)

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
brew install cmake go
```

### Linux(Ubuntu)

```Shell
# install dependencies using APT package Manager
apt-get install -y build-essential golang cmake
```

cmake version 3.14.2 or lower, download from website and install cmake.
(https://cmake.org/download/)

go version 1.11 or lower, get `golang.org/dl/go1.13` or higher.
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
cmake .. (CMake options) -DENABLE_JS_WRAPPER=off
make
cd ..
go build
```

**CMake options**

- `-DENABLE_ELEMENTS`: Enable functionalies for elements sidechain. [ON/OFF] (default:ON)
- `-DENABLE_SHARED`: Enable building a shared library. [ON/OFF] (default:OFF)
- `-DENABLE_TESTS`: Enable building a testing codes. If enables this option, builds testing framework submodules(google test) automatically. [ON/OFF] (default:ON)
- `-DCMAKE_BUILD_TYPE=Release`: Enable release build.
- `-DCMAKE_BUILD_TYPE=Debug`: Enable debug build.
- `-DCFDCORE_DEBUG=on`: Enable cfd debug mode and loggings log files. [ON/OFF] (default:OFF)

---

## install / uninstall

### install (after build)

install for `/usr/local/lib`.

#### Using cmake-js install

When using the cmake-js package and npm script, the options for compilation are already set.

```Shell
npm cmake_make_install
(Enter the password when prompted to use the sudo command.)
```

cmake version is 3.15 or higher:
```Shell
npm cmake_install
(Enter the password when prompted to use the sudo command.)
```

#### Using CMake install

```Shell
cd build && sudo make install
```

cmake version is 3.15 or higher: `cmake --install build`

### uninstall
```Shell
cd build && sudo make uninstall
```

---

## How to use cfd-go as go module

1. Once, clone this repository.
2. Build & install cfd-go(and dependencies).
3. Modify `go.mod` file adding cfd-go as go moudle

go.mod

```
require (
  github.com/cryptogarageinc/cfd-go v0.0.2
  ...
)
```

Reference github commit:
```
require (
  github.com/cryptogarageinc/cfd-go v1.0.0-0.20191205091101-a48a6a8b1a24
  ...
)
```
(version format: UnknownVersionTag-UtcDate-CommitHash)

4. Download cfd-go module

```Shell
go mod download
```

---

## Example

### Test

```Shell
LD_LIBRARY_PATH=./build/Release go test
```

### Example

- cfdgo_test.go