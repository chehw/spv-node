#!/bin/bash

TARGET=${1-"mining-gpu"}
TARGET=$(basename "${TARGET}")
TARGET=${TARGET/.[ch]/}

echo "target: $TARGET"

CC="gcc -std=gnu99 -Wall -D_DEFAULT_SOURCE -D_GNU_SOURCE"
LINKER="$CC"

CFLAGS=" -I../include -I../include/crypto -I../utils -I../src "
CFLAGS+=" -g -D_DEBUG "

#~ OPTIMIZE=" -O2 "

LIBS=" -lm -lpthread -ljson-c -lcurl -ldb -lsecp256k1 -lgmp -lgnutls "


case "$TARGET" in
	hash256)
		${CC} ${OPTIMIZE} -o hash256 hash256.c \
			../utils/utils.c \
			$CFLAGS $LIBS
		;;
	reverse)
		${CC} ${OPTIMIZE} -o reverse_hex reverse.c \
			../utils/auto_buffer.c \
			$CFLAGS $LIBS
		;;
	hash256-gpu)
		${CC} ${OPTIMIZE} -o hash256-gpu \
			hash256-gpu.c opencl-context.c \
			../utils/utils.c \
			$CFLAGS $LIBS \
			-lOpenCL
		;;
	opencl-context)
		${CC} ${OPTIMIZE} -D_TEST_OPENCL_CONTEXT -D_STAND_ALONE \
			-o test_opencl-context opencl-context.c \
			$CFLAGS $LIBS \
			-lOpenCL
		;;
	*)
		exit 1
		;;
esac

