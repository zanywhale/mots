#!/bin/sh
./configure CC=mipseb-linux-musl-gcc --host=mips-linux --with-pcap=linux
make
