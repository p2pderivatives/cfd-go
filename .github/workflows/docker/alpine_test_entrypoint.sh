#!/bin/sh -l

apk add --update --no-cache musl gcc g++ make

cd /github/workspace/dist
cp -rf usr /
ls -l /usr/local/*
ls -l /usr/local/go/bin

env
cd /github/workspace
echo "---- go test start ----"
LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib64:/usr/local/lib" /usr/local/go/bin/go test
echo "---- go test end ----"
