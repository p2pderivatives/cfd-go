#!/bin/sh

sudo rm -rf /usr/local/include/wally.hpp /usr/local/include/wally_*.h /usr/local/include/secp256k1*.h
sudo rm -rf /usr/local/include/cfdcore /usr/local/include/univalue.h
sudo rm -rf /usr/local/include/cfd /usr/local/include/cfdc
sudo rm -rf /usr/local/lib/libwally.so /usr/local/lib/libwallycore.so
sudo rm -rf /usr/local/lib/libcfdcore.so /usr/local/lib/libunivalue.so
sudo rm -rf /usr/local/lib/libcfd.so
sudo rm -rf /usr/local/lib/pkgconfig/wallycore.pc /usr/local/lib/pkgconfig/wally.pc
sudo rm -rf /usr/local/lib/pkgconfig/libunivalue.pc /usr/local/lib/pkgconfig/libunivalue-uninstalled.pc
sudo rm -rf /usr/local/lib/pkgconfig/cfd.pc /usr/local/lib/pkgconfig/cfd-core.pc
sudo rm -rf /usr/local/cmake/cfd*.cmake /usr/local/cmake/univalue-*.cmake
sudo rm -rf /usr/local/cmake/wally-*.cmake /usr/local/cmake/wallycore-*.cmake
