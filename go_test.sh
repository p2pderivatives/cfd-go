#!/bin/sh
if [ -z "$GO_EXEC_PATH" ]; then
GO_EXEC_PATH=go
fi
LIB_PATH=./build/Release:../build/Release:../../build/Release

LD_LIBRARY_PATH=$LIB_PATH $GO_EXEC_PATH test . ./types/... ./errors ./utils ./config ./apis/... ./service/... ./tests -v
