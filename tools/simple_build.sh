#!/bin/sh
cd `git rev-parse --show-toplevel`

cmake -S . -B build -G "Unix Makefiles" -DENABLE_SHARED=off -DENABLE_JS_WRAPPER=off -DENABLE_TESTS=off -DENABLE_CAPI=on -DENABLE_ELEMENTS=on -DCMAKE_BUILD_TYPE=Release -DTARGET_RPATH="/usr/local/lib;./build/Release"

cmake --build build --config Release --parallel 4
