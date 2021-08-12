TARGET=spv-node
BIN_DIR = bin
DATA_DIR = data
LOG_DIR = log

DEBUG ?= 1
OPTIMIZE ?= -O2

CC=gcc -std=gnu99 -D_DEFAULT_SOURCE -D_GNU_SOURCE
LINKER=$(CC)
AR=ar crf

CFLAGS = -Wall -Iinclude -Iutils -Iinclude/crypto
LIBS = -lm -lpthread

ifeq ($(DEBUG),1)
CFLAGS += -g -D_DEBUG
OPTIMIZE = -O0
endif

LIBS += -ldb -ljson-c -lcurl

# sha256 / ripemd160
CFLAGS += $(shell pkg-config --cflags gnutls)
LIBS += $(shell pkg-config --libs gnutls) -lgmp

# ecc/ecdsa - secp256k1
CFLAGS += $(shell pkg-config --cflags libsecp256k1)
LIBS += $(shell pkg-config --libs libsecp256k1)

DEPS = 
SRC_DIR = src
OBJ_DIR = obj
SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

BASE_SRC_DIR = src/base
BASE_OBJ_DIR = obj/base
BASE_SOURCES := $(wildcard $(BASE_SRC_DIR)/*.c)
BASE_OBJECTS := $(BASE_SOURCES:$(BASE_SRC_DIR)/%.c=$(BASE_OBJ_DIR)/%.o)

UTILS_SRC_DIR = utils
UTILS_OBJ_DIR = obj/utils
UTILS_SOURCES := $(wildcard $(UTILS_SRC_DIR)/*.c)
UTILS_OBJECTS := $(UTILS_SOURCES:$(UTILS_SRC_DIR)/%.c=$(UTILS_OBJ_DIR)/%.o)

GCLOUD_UTILS_SRC_DIR = src/gcloud
GCLOUD_UTILS_OBJ_DIR = obj/gcloud
GCLOUD_UTILS_SOURCES := $(wildcard $(GCLOUD_UTILS_SRC_DIR)/*.c)
GCLOUD_UTILS_OBJECTS := $(GCLOUD_UTILS_SOURCES:$(GCLOUD_UTILS_SRC_DIR)/%.c=$(GCLOUD_UTILS_OBJ_DIR)/%.o)

all: do_init $(BIN_DIR)/$(TARGET)
	echo "gcloud objs_dir: $(GCLOUD_UTILS_OBJ_DIR)"

$(BIN_DIR)/$(TARGET): $(OBJECTS) $(BASE_OBJECTS) $(UTILS_OBJECTS) $(GCLOUD_UTILS_OBJECTS)
	$(LINKER) $(OPTIMIZE) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJECTS): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS)
	$(CC) -o $@ -c $< $(CFLAGS)

$(BASE_OBJECTS): $(BASE_OBJ_DIR)/%.o: $(BASE_SRC_DIR)/%.c $(DEPS)
	$(CC) -o $@ -c $< $(CFLAGS)

$(UTILS_OBJECTS): $(UTILS_OBJ_DIR)/%.o: $(UTILS_SRC_DIR)/%.c $(DEPS)
	$(CC) -o $@ -c $< $(CFLAGS)
	
$(GCLOUD_UTILS_OBJECTS): $(GCLOUD_UTILS_OBJ_DIR)/%.o : $(GCLOUD_UTILS_SRC_DIR)/%.c $(DEPS)
	echo "souce: $<"
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: do_init clean
do_init:
	mkdir -p $(BIN_DIR) $(OBJ_DIR) $(BASE_OBJ_DIR) $(UTILS_OBJ_DIR) $(GCLOUD_UTILS_OBJ_DIR)
	mkdir -p $(DATA_DIR) $(LOG_DIR)

clean:
	rm -f $(BIN_DIR)/$(TARGET) $(OBJECTS) $(UTILS_OBJECTS) $(GCLOUD_UTILS_OBJECTS)
