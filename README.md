# Crypto Finance Development Kit for Go (CFD-GO)

CFD library for Go.

## Overview

This library is development kit for crypto finance application.
Useful when developing applications for cryptocurrencies.

### Target Network

- Bitcoin
- Liquid Network

### Support function by cfd

- Bitcoin
  - Bitcoin Script (builder, viewer)
  - Transaction
    - Create, Parse, Decode
    - Simple pubkey-hash sign / verify
    - Estimate Fee
    - Coin Selection (FundRawTransaction)
  - PSBT (v0. v2 & taproot is not yet.)
    - Create, Parse, Decode
    - Simple pubkey-hash sign / verify
    - Estimate Fee
    - Coin Selection (FundRawTransaction)
  - ECDSA Pubkey/Privkey (TweakAdd/Mul, Negate, Sign, Verify)
  - BIP32, BIP39
  - Output Descriptor (contains miniscript parser)
  - Schnorr/Taproot
  - Bitcoin Address (Segwit-v0, Segwit-v1, P2PKH/P2SH)
- Liquid Network
  - Confidential Transaction
    - Blind, Unblind
    - Reissuance
  - Confidential Address

### Libraries for each language

- Go : cfd-go
  - C/C++ : cfd
    - Extend the cfd-core library. Defines the C language API and extension classes.
  - C++ : cfd-core
    - Core library. Definition base class.
- other language:
  - JavaScript : cfd-js
  - WebAssembly : cfd-js-wasm
  - Python : cfd-python
  - C# : cfd-csharp
  - Rust : cfd-rust

## Dependencies

- Go (1.12 or higher)
- C/C++ Compiler
  - can compile c++11
- CMake (3.14.3 or higher)
- When using npm scripts and cmake-js
  - node.js (stable version)
  - Python 3.x
    - for building libwally-core js wrapper

### Windows (MinGW)

attention: Cgo can only be used on the `make` platform.

(Recommended to use wsl(Windows Subsystem for Linux), because it can be cumbersome.)

download and install files.
- go (1.12 or higher)
- [CMake](https://cmake.org/) (3.14.3 or higher)
- [MinGW](http://mingw-w64.org/) (Add to PATH after install)

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
go mod download
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
go mod download
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

On Windows, can use `releases asset`.

### Using releases asset

The fastest and easiest way.

- macos / linux(ubuntu)
```Shell
(cleanup)
./tools/cmake_cleanup.sh
sudo ./tools/cleanup_install_files.sh

(download)
wget https://github.com/p2pderivatives/cfd-go/releases/download/v0.3.0/cfdgo-v0.1.5-ubuntu1804-gcc-x86_64.zip

(unzip)
sudo unzip -q cfdgo-v0.1.5-ubuntu1804-gcc-x86_64.zip -d /
```

- windows
  1. cleanup: `c:/usr/local` directory.
  2. download: https://github.com/p2pderivatives/cfd-go/releases/download/v0.3.0/cfdgo-v0.1.5-win-gcc-static-x86_64.zip
  3. Unzip and extract to `c:/usr/local` directory.

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

#### Using releases asset

- Ubuntu / MacOS
```Shell
(cleanup)
./tools/cmake_cleanup.sh
sudo ./tools/cleanup_install_files.sh

(download)
wget https://github.com/p2pderivatives/cfd-go/releases/download/v0.3.0/cfdgo-v0.3.0-ubuntu1804-gcc-x86_64.zip

(unzip)
sudo unzip -q cfdgo-v0.1.34-ubuntu1804-gcc-x86_64.zip -d /
```

- Windows
  1. get releases asset. (ex. https://github.com/p2pderivatives/cfd-go/releases/download/v0.3.0/cfdgo-v0.3.0-win-gcc-static-x86_64.zip )
  2. Expand to PATH

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
  github.com/p2pderivatives/cfd-go v0.3.0
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

## Test and Example

### Test

test file is `cfdgo_test.go` . Execute by the following method.

- shell script or bat file
```
(linux/macos)
./go_test.sh

(Windows)
.\go_test.bat
```

- go command (linux/macos)
```Shell
LD_LIBRARY_PATH=./build/Release go test
```

### Example

- cfdgo_test.go

---

## Information for developers

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

### using library

- cfd
  - cfd-core
    - [libwally-core](https://github.com/cryptogarageinc/libwally-core/tree/cfd-develop) (forked from [ElementsProject/libwally-core](https://github.com/ElementsProject/libwally-core))
    - [univalue](https://github.com/jgarzik/univalue) (for JSON encoding and decoding)

### formatter

- go fmt (ignore cfdgo.go)

### support compilers

- GCC (contains MinGW) (5.x or higher)
- Clang (7.x or higher)

### code coverage

```
(Windows)
.\go_coverage.bat

(Ubuntu / MacOS)
./go_coverage.sh
```

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

### Ignore git update for CMake External Project:

Depending on your git environment, you may get the following error when checking out external:
```
  Performing update step for 'libwally-core-download'
  Current branch cmake_build is up to date.
  No stash entries found.
  No stash entries found.
  No stash entries found.
  CMake Error at /workspace/cfd-core/build/external/libwally-core/download/libwally-core-download-prefix/tmp/libwally-core-download-gitupdate.cmake:133 (message):


    Failed to unstash changes in:
    '/workspace/cfd-core/external/libwally-core/'.

    You will have to resolve the conflicts manually
```

This phenomenon is due to the `git update` related command.
Please set an environment variable that skips update processing.

- Windows: (On the command line. Or set from the system setting screen.)
```
set CFD_CMAKE_GIT_SKIP_UPDATE=1
```

- MacOS & Linux(Ubuntu):
```
export CFD_CMAKE_GIT_SKIP_UPDATE=1
```
