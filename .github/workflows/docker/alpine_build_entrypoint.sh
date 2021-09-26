#!/bin/sh -l

apk add --update --no-cache musl gcc g++ make git cmake

cd /github/workspace
ls

mkdir dist
cd cfd-go
mkdir build
cd build
cmake --version
cmake .. -DENABLE_SHARED=on -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=off -DENABLE_JS_WRAPPER=off -DENABLE_CAPI=on -DTARGET_RPATH="/usr/local/lib;/usr/local/lib64"
make
make install DESTDIR=/github/workspace/dist
ls /github/workspace/dist
ls /github/workspace/dist/usr
ls /github/workspace/dist/usr/local
ls /github/workspace/dist/usr/local/lib*
