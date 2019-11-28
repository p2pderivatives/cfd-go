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

<!--

### Windows (MinGW)

attention: Cgo can only be used on the `make` platform.

- MinGW (http://www.mingw.org/)
  - download and install files.
    - go (1.12 or higher)
    - MinGW
      - 

future: After supporting autotools, it can be run on MSYS2.

-->

### MacOS

- [Homebrew](https://brew.sh/)

```Shell
# xcode cli tools
xcode-select --install

# install dependencies using Homebrew
brew install cmake python node
```

### Linux(Ubuntu)

```Shell
# install dependencies using APT package Manager
apt-get install -y build-essential golang cmake python nodejs
```

cmake version 3.14.2 or lower, download from website and install cmake.
(https://cmake.org/download/)

go version 1.11 or later, get `golang.org/dl/go1.13` or higher.
(https://www.mazn.net/blog/2019/02/03/1704.html)

---

## Build

### Using cmake-js

When using the cmake-js package and npm script, the options for compilation are already set.

```Shell
npm install
npm run cmake_all
go build
```

### Use CMake

```Shell
# recommend out of source build
mkdir build && cd $_
# configure & build
cmake .. (CMake options)
make
cd ..
go build
```

**CMake options**

- `-DENABLE_ELEMENTS`: Enable functionalies for elements sidechain. [ON/OFF] (default:ON)
- `-DENABLE_DEBUG`: Enable debug loggings and log files. [ON/OFF] (default:OFF)
- `-DENABLE_SHARED`: Enable building a shared library. [ON/OFF] (default:OFF)
- `-DENABLE_TESTS`: Enable building a testing codes. If enables this option, builds testing framework submodules(google test) automatically. [ON/OFF] (default:ON)

---

## install / uninstall

### install (after build)

install for `/usr/local/lib`.

```Shell
cd build && sudo make install
```

### uninstall
```Shell
cd build && sudo make uninstall
```

## Example

### Test

```Shell
LD_LIBRARY_PATH=./build/Release go test
```

### Example

- cfdgo_test.go