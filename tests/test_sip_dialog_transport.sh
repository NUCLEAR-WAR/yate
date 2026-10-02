#!/bin/sh
# Run from a configured Yate source tree; requires a C++11-capable compiler.
set -eu
cd "$(dirname "$0")/.."
make -j2 engine
make -C modules -j2 ysipchan.yate
test_binary=$(mktemp "${TMPDIR:-/tmp}/yate-sip-transport.XXXXXX")
trap 'rm -f "$test_binary"' EXIT HUP INT TERM
${CXX:-c++} -std=c++11 -O2 -fno-exceptions -DHAVE_GCC_FORMAT_CHECK \
    -DHAVE_BLOCK_RETURN -DATOMIC_OPS -I. -Ilibs/ysip -Ilibs/ysdp \
    tests/sip_dialog_transport.cpp -L. -Llibs/ysip -Llibs/ysdp \
    -lyatesip -lyatesdp -lyate -lresolv -lpthread -Wl,-rpath,"$(pwd)" \
    -o "$test_binary"
"$test_binary"
