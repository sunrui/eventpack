INCLUDE = \
	-I../../3rdparty/bson/src \
	-I../../3rdparty/bzip2 \
	-I../../3rdparty/libuv/include \
	-I../../3rdparty/libuv/include/uv-private \
	-I../../3rdparty/libuv/src \
	-I../../3rdparty/libuv/src/unix \
	-I../../3rdparty/jemalloc/include \
	-I../../include \
	-I../../src \
	-I../../utils \
	-I3rdparty/openssl/include \
	-I3rdparty/jemalloc/include

BSON_SOURCE = \
	../../3rdparty/bson/src/bson.c \
	../../3rdparty/bson/src/encoding.c \
	../../3rdparty/bson/src/numbers.c

BZIP2_SOURCE = \
	../../3rdparty/bzip2/blocksort.c \
	../../3rdparty/bzip2/bzlib.c \
	../../3rdparty/bzip2/compress.c \
	../../3rdparty/bzip2/crctable.c \
	../../3rdparty/bzip2/decompress.c \
	../../3rdparty/bzip2/huffman.c \
	../../3rdparty/bzip2/randtable.c \

LIBUV_SOURCE =  \
	../../3rdparty/libuv/src/unix/async.c \
	../../3rdparty/libuv/src/unix/core.c \
	../../3rdparty/libuv/src/unix/dl.c \
	../../3rdparty/libuv/src/unix/fs.c \
	../../3rdparty/libuv/src/unix/getaddrinfo.c \
	../../3rdparty/libuv/src/unix/linux-core.c \
	../../3rdparty/libuv/src/unix/linux-inotify.c \
	../../3rdparty/libuv/src/unix/linux-syscalls.c \
	../../3rdparty/libuv/src/unix/proctitle.c \
	../../3rdparty/libuv/src/unix/loop.c \
	../../3rdparty/libuv/src/unix/loop-watcher.c \
	../../3rdparty/libuv/src/unix/pipe.c \
	../../3rdparty/libuv/src/unix/poll.c \
	../../3rdparty/libuv/src/unix/process.c \
	../../3rdparty/libuv/src/unix/signal.c \
	../../3rdparty/libuv/src/unix/stream.c \
	../../3rdparty/libuv/src/unix/tcp.c \
	../../3rdparty/libuv/src/unix/thread.c \
	../../3rdparty/libuv/src/unix/threadpool.c \
	../../3rdparty/libuv/src/unix/timer.c \
	../../3rdparty/libuv/src/unix/tty.c \
	../../3rdparty/libuv/src/unix/udp.c \
	../../3rdparty/libuv/src/fs-poll.c \
	../../3rdparty/libuv/src/inet.c \
	../../3rdparty/libuv/src/uv-common.c \
	../../3rdparty/libuv/src/version.c

EVENTPACK_SOURCE = \
	../../src/ep_alloctor.c \
	../../src/ep_alloctor.c \
	../../src/ep_buffer.c \
	../../src/ep_cert.c \
	../../src/ep_client.c \
	../../src/ep_compress.c \
	../../src/ep_crypt.c \
	../../src/ep_dispatch.c \
	../../src/ep_io.c \
	../../src/ep_packet.c \
	../../src/ep_queue.c \
	../../src/ep_request.c \
	../../src/ep_ringbuffer.c \
	../../src/ep_service.c \
	../../src/ep_service_libuv.c \
	../../src/ep_threadpool.c \
	../../src/ep_util.c

SAMPLE_SOURCE = \
	../../sample/main.c \
	../../sample/client.c \
	../../sample/server.c \
	../../sample/testcase.c

SOURCE = \
	$(BSON_SOURCE) \
	$(BZIP2_SOURCE) \
	$(LIBUV_SOURCE) \
	$(EVENTPACK_SOURCE)

OPENSSL_LIBRARY = -L3rdparty/openssl/lib -lcrypto -lssl
JEMALLOC_LIBRARY = -L3rdparty/jemalloc/lib/ -ljemalloc_pic

# for mongo bson
CFALGS += -DMONGO_HAVE_STDINT
# for malloc
CFALGS += -DUSE_LOCKS -DUSE_DL_PREFIX
# for libuv
CFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
# for eventpack service
CFLAGS += -DEP_HAVE_SERVER
# for jemalloc
CFLAGS += -DJEMALLOC_NO_DEMANGLE

CFLAGS += -DLINUX -D_GNU_SOURCE
CFALGS += -O3 -s -DNDEBUG -fPIC
CFLAGS += -pthread --std=gnu99 -Wall -Wextra -Wno-unused-parameter

CC = gcc
CXX = g++
ARFLAGS = cr
LIB = -ldl -lrt $(OPENSSL_LIBRARY) $(JEMALLOC_LIBRARY)

#doing this before run: export LD_LIBRARY_PATH=./

TARGET = libeventpack.so
SAMPLE = sample

all: clean $(TARGET) $(SAMPLE)

clean:
	@-rm -f *.d *.o *.so eventpack* sample*

$(TARGET):$(SOURCE)
	@$(CC) $(CFLAGS) -shared -o $@ $^ $(INCLUDE) $(LIB)

$(SAMPLE):$(SAMPLE_SOURCE)
	@$(CC) $(CFLAGS) -o $@ $^ $(INCLUDE) $(LIB) -L. -leventpack

