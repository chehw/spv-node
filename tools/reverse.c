/*
 * reverse.c
 * 
 * Copyright 2021 chehw <hongwei.che@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <errno.h>
#include <stdint.h>
#include "auto_buffer.h"

static void reverse_hex(char * hex, int length)
{
	assert((length %2) == 0);
	
	length /= 2;
	uint16_t * u16 = (uint16_t * )hex;
	
	for(int i = 0; i < length / 2; ++i) {
		uint16_t tmp = u16[i];
		u16[i] = u16[length - 1 - i];
		u16[length - 1 - i] = tmp;
	}
	return;
}

static void show_help(const char * app_name)
{
	fprintf(stderr, 
		"Usuage: %s [hex_file]\n"
		"Examples: \n"
		"    read from stdin: %s \n"
		"    read from pipe: echo \"<message text>\" | %s \n"
		"    read from file: %s filename.hex\n",
		app_name, 
		app_name,
		app_name,
		app_name
	);
}

int main(int argc, char **argv)
{
	FILE * fp = stdin;
	
	if(argc > 1) {
		fp = fopen(argv[1], "r");
		if(NULL == fp) {
			fprintf(stderr, "[ERROR]: open file '%s' failed: %s\n", argv[1], strerror(errno));
			
			show_help(argv[0]);
			exit(1);
		}
	}
	
	auto_buffer_t input[1];
	auto_buffer_init(input, 0);
	
	while(1) {
		char buf[4096 + 1] = "";
		char * line = fgets(buf, 4096, fp);
		if(NULL == line) break;
		
		ssize_t cb = strlen(line);
		assert(cb > 0);
		
		auto_buffer_push(input, buf, cb);
		if(input->data[input->length - 1] != '\n') continue;
		
		input->data[--input->length] = '\0';
		
		if(input->length % 2) {
			fprintf(stderr, "[ERROR]: invalid format.\n");
			input->start_pos = 0;
			input->length = 0;
			continue;
		}
		
		
		reverse_hex((char *)input->data, input->length);
		printf("%s\n", (char *)input->data);
		
		input->start_pos = 0;
		input->length = 0;
	}
	
	auto_buffer_cleanup(input);
	
	fclose(fp);
	return 0;
}

