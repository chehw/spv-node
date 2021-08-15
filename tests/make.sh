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
		
	bitcoin-message|test_bitcoin-messages|bitcoin_message_*)
		${LINKER} -g ${CFLAGS} \
			-o test_bitcoin-messages test_bitcoin-messages.c \
			../src/spv-node.c ../src/spv_node_message_handlers.c \
			../src/bitcoin-message.c ../src/bitcoin-messages/*.c \
			../src/base/*.c \
			../utils/*.c \
			${LIBS} -lgnutls -lgmp -lcurl -lsecp256k1
		RET=$?
		;;
	*)
		echo "build nothing"
		exit 1
		;;
esac

exit ${RET}
