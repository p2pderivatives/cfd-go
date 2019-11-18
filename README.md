# Crypto Finance Development Kit for Go (CFD-GO)

<!-- TODO: Write Summary and Overview

## Overview

-->

## Dependencies

- C/C++ Compiler
  - can compilefe c++11
- CMake (3.14.3 or higher)
- Python 3.x
- node.js (stable version)

### Windows (autotools for mingw or MSYS2)

download and install files.
- go (1.12 or higher)
- autotools

### MacOS

- [Homebrew](https://brew.sh/)

```Shell
# xcode cli tools
xcode-select --install

# install dependencies using Homebrew
brew install cmake python node
```

### Linux(Ubuntsu)

```Shell
# install dependencies using APT package Manager
apt-get install -y build-essential cmake python nodejs
```

cmake version 3.14.2 or lower, download from website and install cmake.
(https://cmake.org/download/)

---

## Build

### Using cmake-js

When using the cmake-js package and npm script, the options for compilation are already set.

```Shell
npm install
npm run cmake_all
```

<!--
NOTICE: CMAKE IS NOT SUPPORT YET UNDER WINDOWS OS

### Use CMake

```Shell
# recommend out of source build
mkdir build && cd $_
# configure & build
cmake .. (CMake options)
make
```

``` (windows) command prompt example
cmake -S . -B build  -G "Visual Studio 16 2019"
cmake -D ENABLE_SHARED=1 --build build
cmake --build build --config Release
```

**CMake options**

- `-DENABLE_ELEMENTS`: Enable functionalies for elements sidechain. [ON/OFF] (default:ON)
- `-DENABLE_DEBUG`: Enable debug loggings and log files. [ON/OFF] (default:OFF)
- `-DENABLE_SHARED`: Enable building a shared library. [ON/OFF] (default:OFF)
- `-DENABLE_TESTS`: Enable building a testing codes. If enables this option, builds testing framework submodules(google test) automatically. [ON/OFF] (default:ON)

-->

---

## Example

### Test

```Shell
npm run ctest
```

### Example

- Not Implemented yet