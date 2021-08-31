#!/bin/bash

target=${1-"google-oauth2"}
target=$(basename "$target")
target=${target/.[ch]/}

LINKER="gcc -std=gnu99 -D_DEFAULT_SOURCE -D_GNU_SOURCE "
CFLAGS=" -Wall -I../include -I../include/crypto -I../utils "
LIBS=" -lm -lpthread -ljson-c -lgnutls "

CFLAGS+=" -D_DEBUG "

RET=0
echo "build '${target}' ..."
case "$target" in
	google-oauth2)
		${LINKER} -g -D_DEBUG ${CFLAGS} \
			-D_TEST_GOOGLE_OAUTH2 -D_STAND_ALONE \
			-o "test_$target" \
			../src/gcloud/google-oauth2.c \
			../utils/*.c \
			${LIBS} -lcurl
		RET=$?
		;;
	gcloud-storage)
		${LINKER} -g -D_DEBUG ${CFLAGS} \
			-D_TEST_GCLOUD_STORAGE -D_STAND_ALONE \
			-o "test_$target" \
			../src/gcloud/gcloud-storage.c \
			../src/gcloud/google-oauth2.c \
			../utils/*.c \
			${LIBS} -lcurl
		RET=$?
		;;
	oauth_jwt-test)
		${LINKER} -g ${CFLAGS} \
			-o oauth_jwt-test \
			oauth_jwt-test.c ../utils/base64.c \
			${LIBS}
		RET=$?
		;;
		
	bitcoin-message|test_bitcoin-messages|bitcoin_message_*|spv-node|spv_node_message_handlers)
		${LINKER} -g ${CFLAGS} \
			-o test_bitcoin-messages test_bitcoin-messages.c \
			../src/spv-node.c ../src/spv_node_message_handlers.c \
			../src/bitcoin-message.c ../src/bitcoin-messages/*.c \
			../src/base/*.c \
			../utils/*.c \
			../src/gcloud/gcloud-storage.c \
			../src/gcloud/google-oauth2.c \
			${LIBS} -lgnutls -lgmp -lcurl -lsecp256k1
		RET=$?
		;;
	test_uint256*|compact_int)
		${LINKER} -g ${CFLAGS} \
			-o test_uint256 test_uint256_algorithms.c \
			../src/base/compact_int.c \
			../utils/utils.c \
			-lm -lgmp -lgnutls
		RET=$?
		;;
		
	block_hdrs-db|test_block_headers_db)
		${LINKER} -g ${CFLAGS} -I../src \
			-o test_block_headers_db test_block_headers_db.c \
			../src/block_hdrs-db.c \
			../src/base/*.c \
			../utils/utils.c \
			-lm -lgmp -lgnutls -ldb -lpthread -lsecp256k1
		RET=$?
		;;
		
	asicboost)
		${LINKER} -g ${CFLAGS} \
			-o test_asicboost asicboost.c \
			-lm -lgmp -lgnutls
		;;
	*)
		echo "build nothing"
		exit 1
		;;
esac

exit ${RET}
