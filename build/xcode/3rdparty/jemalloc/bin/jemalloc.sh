#!/bin/sh

prefix=/Users/Smallrui/Documents/Project/eventpack/trunk/3rdparty/jemalloc/honeysense
exec_prefix=/Users/Smallrui/Documents/Project/eventpack/trunk/3rdparty/jemalloc/honeysense
libdir=${exec_prefix}/lib

DYLD_INSERT_LIBRARIES=${libdir}/libjemalloc.1.dylib
export DYLD_INSERT_LIBRARIES
exec "$@"
