#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sha.h"
#include "utils.h"

#define ALLOC_SIZE (65536)

#include <errno.h>
#include <endian.h>
#include <byteswap.h>
static void reverse_bytes(unsigned char * data, int size)
{
	if(0 == (size % 8)) {
		uint64_t * u64 = (uint64_t *)data;
		int length = size / 8;
		
		for(int i = 0; i < length / 2; ++i) {
			uint64_t tmp = bswap_64(u64[i]);
			u64[i] = bswap_64(u64[length - 1 - i]);
			u64[length - 1 - i] = tmp;
		}
		return;
	}
	
	for(int i = 0; i < size / 2; ++i) {
		unsigned char tmp = data[i];
		data[i] = data[size - 1 - i];
		data[size - 1 - i] = tmp;
	}
	return;
}

int main(int argc, char ** argv)
{
	unsigned char hash[32] =  { 0 };

	ssize_t msg_buffer_size = ALLOC_SIZE;
	ssize_t msg_len = 0;
	ssize_t cur_pos = 0;
	char * msg_data_hex = calloc(msg_buffer_size, 1);
	
	assert(msg_data_hex);
	FILE * fp = stdin;
	
	if(argc > 1) {
		fp = fopen(argv[1], "r");
		if(NULL == fp) {
			fprintf(stderr, "[ERROR]: open file '%s' failed: %s\n", argv[1], strerror(errno));
			
			fprintf(stderr, 
				"Usuage: %s [hex_file]\n"
				"Examples: \n"
				"    read from stdin: %s \n"
				"    read from pipe: echo \"aabbccddeeff001122\" | %s \n"
				"    read from file: %s filename.hex\n",
				argv[0], 
				argv[0],
				argv[0],
				argv[0]
			);
				
		}
	}
	
	while(1) {
		char buf[4096 + 1] = "";
		char * line = fgets(buf, 4096, fp);
		if(NULL == line) break;
		
		ssize_t cb = strlen(line);
		assert(cb > 0);
		
		if((msg_len + cb) > msg_buffer_size) {
			ssize_t new_size = (msg_len + cb + ALLOC_SIZE - 1) / ALLOC_SIZE + ALLOC_SIZE;
			msg_data_hex = realloc(msg_data_hex, new_size + 1);
			assert(msg_data_hex);
			msg_data_hex[new_size] = '\0';
		}
		memcpy(msg_data_hex + cur_pos, buf, cb);
		msg_len += cb;
		
		if(msg_data_hex[msg_len - 1] != '\n') 
		{
			cur_pos = msg_len;
			continue;
		}
			
		msg_data_hex[--msg_len] = '\0';
		unsigned char * msg_data = NULL;
		ssize_t cb_msg = hex2bin(msg_data_hex, msg_len, (void **)&msg_data);
		
		if(cb_msg < 0) {
			fprintf(stderr, "[ERROR]: invalid hex format.\n");
			cur_pos = 0;
			msg_len = 0;
			continue;
		}
		
		assert(cb_msg >= 0);
		if(cb_msg > 0) {
			hash256(msg_data, cb_msg, hash);
			
			static int display_width = 128;
			printf("\e[33m" "[msg_hex(cb=%ld)]: %.*s" "\e[39m" "\n", (long)msg_len, 
				(msg_len >display_width)?display_width:(int)msg_len, 
				msg_data_hex);
			
			printf("==> hash: ");
			dump(hash, 32);
			printf("\n");
			
			reverse_bytes(hash, 32);
			printf("reversed: ");
			dump(hash, 32);
			printf("\n");
			
		}
		free(msg_data);
		
		cur_pos = 0;
		msg_len = 0;
	}
	
	fclose(fp);
    return 0;
}
