/*
 * hash256-gpu.c
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

#include <time.h>
#include <unistd.h>

#include "opencl-context.h"
#include "utils.h"


struct program_build_context
{
//	cl_context ctx;
	int num_devices;
	cl_device_id * device_ids; 
};

static void on_build_notify(cl_program program, void * user_data)
{
	cl_int ret = 0;
	
	struct program_build_context * build_ctx = user_data;
	assert(build_ctx);
	
	cl_device_id * device_ids = build_ctx->device_ids;
	for(int i = 0; i <build_ctx->num_devices; ++i)
	{
		char param_value[4096] = "";
		size_t cb_param = 0;
		printf("build on device[%d](%p): ", i, device_ids[i]);
		ret = clGetProgramBuildInfo(program, device_ids[i], CL_PROGRAM_BUILD_STATUS, sizeof(param_value), param_value, &cb_param);
		cl_check_error(ret, "clGetProgramBuildInfo::build-status");
		
		int status = *(int *)param_value;
		printf("build-status: %d ==> [%s]\n", status, (0==status)?"OK":"NG");
		
		if(status) {
			ret = clGetProgramBuildInfo(program, device_ids[i], CL_PROGRAM_BUILD_LOG, sizeof(param_value), param_value, &cb_param);
			printf("build log: %s\n", param_value);
		}
	}
	return;
}

void test_hash256_gpu(cl_context ctx, cl_program program, int num_devices, cl_device_id * device_ids);
int main(int argc, char **argv)
{
	opencl_context_t * cl = opencl_context_new(NULL);
	
	//~ struct opencl_device_info ** infos = NULL
	cl_device_id * device_ids = NULL;
	ssize_t num_devices = opencl_get_devices(cl, -1, CL_DEVICE_TYPE_GPU, "nvidia", &device_ids, NULL);
	assert(num_devices > 0);
	
	cl_int ret = 0;
	cl_context ctx = clCreateContext(NULL, num_devices, device_ids, NULL, NULL, &ret);
	cl_check_error(ret, "clCreateContext");
	
#define NUM_SOURCES (1)
	char * hash256_cl_source = NULL;
	size_t cb_hash256_source = load_file("opencl/hash256.cl", &hash256_cl_source);
	assert(cb_hash256_source > 0);

	const char * sources[NUM_SOURCES] = { 
		[0] = hash256_cl_source,
	};
	size_t cb_sources[NUM_SOURCES] = {
		[0] = cb_hash256_source,
	};
	
	struct program_build_context build_ctx = {
		.num_devices = num_devices,
		.device_ids = device_ids,
	};
	
	cl_program program = clCreateProgramWithSource(ctx, 1, sources, cb_sources, &ret);
	cl_check_error(ret, "clCreateProgramWithSource");
	
	ret = clBuildProgram(program, num_devices, device_ids, NULL, on_build_notify, &build_ctx);
	cl_check_error(ret, "clBuildProgram");
	
	test_hash256_gpu(ctx, program, num_devices, device_ids);

	clReleaseProgram(program);
	clReleaseContext(ctx);
	free(device_ids);
	opencl_context_free(cl);
	return 0;
}


#define NUM_ITEMS (4096)
struct test_data
{
	unsigned char part1[64];
	unsigned char part2[16];
	// unsigned char paddings[48]; 
};
struct nonce_status
{
	uint32_t status;
	uint32_t nonce;
	unsigned char hash[32];
}__attribute__((packed));

volatile uint32_t s_stop_flags = 0;
void test_hash256_gpu(cl_context ctx, cl_program program, int num_devices, cl_device_id * device_ids)
{
	cl_int ret = 0;
	cl_mem gpu_input = NULL;
	cl_mem gpu_output = NULL;
	cl_mem gpu_flags = NULL;
	
	cl_kernel kernel = clCreateKernel(program, "hash256", &ret);
	cl_check_error(ret, "clCreateKernel(hash256)");
	
	cl_command_queue * queues = calloc(num_devices + 1, sizeof(*queues));
	for(int i = 0; i < num_devices; ++i) {
		queues[i] = clCreateCommandQueue(ctx, device_ids[i], CL_QUEUE_PROFILING_ENABLE, &ret);
		cl_check_error(ret, "clCreateCommandQueue");
	}
	
	int total_items = num_devices * NUM_ITEMS;
	
	struct test_data * data = calloc(total_items, sizeof(*data));
	struct nonce_status * results = calloc(total_items, sizeof(*results));
	
	gpu_input = clCreateBuffer(ctx, CL_MEM_READ_ONLY, sizeof(*data) * total_items, NULL, &ret);
	gpu_output = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(*results) * total_items, NULL, &ret);
	gpu_flags = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(uint32_t), NULL, &ret);
	
	
	// prepare data
	uint32_t timestamp = time(NULL);
	for(int i = 0; i < total_items; ++i) {
		unsigned char * item = (unsigned char *)&data[i];
		// set dummy data
		*(int32_t *)item = 0x20000002;
		memcpy(item + 4, "prev_hash", 10);
		memcpy(item + 36, "merkel_root", 12);
		*(uint32_t *)(item + 68) = timestamp + i;
		*(uint32_t *)(item + 72) = 0x1F00FFFF;
	}
	
	cl_event events[num_devices];
	memset(events, 0, sizeof(cl_event) * num_devices);
	
	app_timer_t timer[1];
	double time_elapsed = 0;
	app_timer_start(timer);
	for(int i = 0; i < num_devices; ++i) {
		size_t size = sizeof(*data) * NUM_ITEMS;
		size_t offset = size * i;
		ret = clEnqueueWriteBuffer(queues[i], gpu_input, CL_FALSE, 
			offset, size, 
			(unsigned char *)data + offset, 
			0, NULL, &events[i]);
		cl_check_error(ret, "clEnqueueWriteBuffer");
	}
	
	ret = clWaitForEvents(num_devices, events);
	cl_check_error(ret, "clWaitForEvents(set inputs)");
	time_elapsed = app_timer_stop(timer);
	printf("set input data: time_elapsed=%.3f ms.\n", time_elapsed * 1000.0);
	
	uint64_t num_items = NUM_ITEMS;
	clSetKernelArg(kernel, 0, sizeof(num_items), &num_items);
	clSetKernelArg(kernel, 1, sizeof(cl_mem), &gpu_input);
	clSetKernelArg(kernel, 2, sizeof(cl_mem), &gpu_output);
	clSetKernelArg(kernel, 3, sizeof(cl_mem), &gpu_flags);
	
	app_timer_start(timer);
	for(int i = 0; i < num_devices; ++i)
	{
		size_t offset = num_items * i;	
		ret = clEnqueueNDRangeKernel(queues[i], kernel, 1, 
			&(size_t){offset},
			&(size_t){num_items},
			&(size_t){1},
			0, NULL, &events[i]);
		cl_check_error(ret, "clEnqueueNDRangeKernel");
	}
	ret = clWaitForEvents(num_devices, events);
	cl_check_error(ret, "clWaitForEvents(NDRangeKernel)");
	time_elapsed = app_timer_stop(timer);
	printf("hash256: time_elapsed=%.3f ms.\n", time_elapsed * 1000.0);
	
	for(int i = 0; i < num_devices; ++i) {
		size_t size = sizeof(*results) * NUM_ITEMS;
		size_t offset = sizeof(*results) * num_items * i; 
		ret = clEnqueueReadBuffer(queues[i], gpu_output, CL_TRUE, 
			offset, size,
			(unsigned char *)results + offset, 0, NULL, NULL);
		cl_check_error(ret, "read outputs");
	}
	for(int i = 0; i < total_items; ++i) {
		if(results[i].status) {
			printf("found by %d, nonce=%u: ", i, results[i].nonce);
			dump_line("hash", results[i].hash, 32);
		}
	}
	
	for(int i = 0; i < num_devices; ++i) {
		clReleaseCommandQueue(queues[i]);
		clReleaseEvent(events[i]);
	}
	
	clReleaseKernel(kernel);
	clReleaseMemObject(gpu_input);
	clReleaseMemObject(gpu_output);
	clReleaseMemObject(gpu_flags);
	free(data);
	free(results);
	
	return;
}
