#!/bin/bash
gcc -std=gnu99 -g -Wall -I../include -I../utils -I../include/crypto \
    -o oauth_jwt-test \
    oauth_jwt-test.c ../utils/base64.c \
    -lm -lpthread -ljson-c -lgnutls
