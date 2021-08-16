/*
 * spv_node_app.c
 * 
 * Copyright 2021 chehw <hongwei.che@gmail.com>
 * 
 * The MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of 
 * this software and associated documentation files (the "Software"), to deal in 
 * the Software without restriction, including without limitation the rights to 
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
 * of the Software, and to permit persons to whom the Software is furnished to 
 * do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <signal.h>
#include <errno.h>

#include "spv-node.h"

void on_signal(int sig);
int main(int argc, char **argv)
{
	signal(SIGINT, on_signal);
	signal(SIGUSR1, on_signal);
	
	int rc = 0;
	spv_node_context_t * spv = spv_node_context_init(NULL, NULL);
	assert(spv);
	
	rc = spv_node_parse_args(spv, argc, argv);
	assert(0 == rc);
	//~ rc = spv_node_load_config(spv, spv->conf_file);
	//~ assert(0 == rc);
	
	rc = spv_node_run(spv, 0);
	
	spv_node_context_cleanup(spv);
	free(spv);
	
	return rc;
}