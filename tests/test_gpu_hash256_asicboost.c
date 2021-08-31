/*
 * test_gpu_hash256_asicboost.c
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

#include <unistd.h>
#include <pthread.h>

#include "satoshi-types.h"
#include "../tools/opencl-context.h"
#include "utils.h"



struct program_build_context
{
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

void test_gpu_hash256_asicboost(cl_context ctx, cl_program program, int num_devices, cl_device_id * device_ids);
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
	size_t cb_hash256_source = load_file("opencl/hash256-asicboost.cl", &hash256_cl_source);
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
	
	test_gpu_hash256_asicboost(ctx, program, num_devices, device_ids);

	clReleaseProgram(program);
	clReleaseContext(ctx);
	free(device_ids);
	opencl_context_free(cl);
	
	free(hash256_cl_source);
	
	return 0;
}


//~ __kernel void hash256_asicboost(
	//~ const uint32_t num_items, 
	//~ const uint32_t restrict s0[static 8], 
	//~ const unsigned char * restrict first_16bytes, 
	//~ struct nonce_status * restrict results, 
	//~ uint32_t * item_index,
	//~ volatile uint32_t * flags)
	
volatile uint32_t s_stop_flags = 0;
struct job_context
{
	cl_context ctx;
	cl_device_id device_id;
	cl_mem gpu_flags;
};
static void * job_manager_thread(void * user_data)
{
	struct job_context *job = user_data;
	assert(job && job->ctx && job->device_id);
	
	int timeout = 30;
	while(!s_stop_flags && (timeout-- > 0))
	{
		sleep(1);
	}
	
	s_stop_flags = 1;
	
	cl_int ret = 0;
	cl_command_queue queue = clCreateCommandQueue(job->ctx, job->device_id, 0, &ret);
	cl_check_error(ret, "create command queue");
	
	uint32_t flags = s_stop_flags;
	ret = clEnqueueWriteBuffer(queue, job->gpu_flags, CL_TRUE, 0, 
		sizeof(uint32_t), &flags, 
		0, NULL, NULL);
	cl_check_error(ret, "CL write flags");
	

	clReleaseCommandQueue(queue);
	pthread_exit(0);
}


struct nonce_status
{
	uint32_t status;
	uint32_t nonce;
	unsigned char hash[32];
}__attribute__((packed));

typedef unsigned char part2_16bytes[16];

typedef union part2_data{
	unsigned char data[64];
	uint32_t u32[16];
	struct {
		uint32_t merkle_root_suffix;
		uint32_t timestamp;
		uint32_t bits;
		uint32_t nonce;
		unsigned char paddings[48];
	}__attribute__((packed));
}part2_data_t;

void sha256_chunk_init(uint32_t * s, const uint32_t * s0);
void sha256_chunk(const uint32_t chunk[static 16], uint32_t s[static 8]);
void test_gpu_hash256_asicboost(cl_context ctx, cl_program program, int num_devices, cl_device_id * device_ids)
{
	cl_int ret = 0;
	cl_mem gpu_s0;
	cl_mem gpu_part2_16bytes = NULL;
	cl_mem gpu_results = NULL;
	cl_mem gpu_item_index = NULL;
	cl_mem gpu_flags = NULL;
	
	cl_kernel kernel = clCreateKernel(program, "hash256_asicboost", &ret);
	cl_check_error(ret, "clCreateKernel(hash256_asicboost)");

#define NUM_ITEMS (4096)
	
	uint32_t num_items = NUM_ITEMS;
	uint32_t total_items = num_devices * num_items;
	uint32_t s0[8];
	
	struct satoshi_block_header hdr[1];
	memset(hdr, 0, sizeof(hdr));
	hdr->version = 0x20000002;
	hdr->bits = 0x1d0FFFFF;
	
	unsigned char * payload = (unsigned char *)hdr;
	sha256_chunk_init(s0, NULL);
	sha256_chunk((uint32_t *)payload, s0);
	for(int i = 0; i < 8; ++i) printf("%.8x ", s0[i]);
	printf("\n");
	
	unsigned char * first_16bytes = payload + 64;
	struct nonce_status * results = calloc(total_items, sizeof(*results));
	
	cl_command_queue * queues = calloc(num_devices + 1, sizeof(*queues));
	for(int i = 0; i < num_devices; ++i) {
		queues[i] = clCreateCommandQueue(ctx, device_ids[i], CL_QUEUE_PROFILING_ENABLE, &ret);
		cl_check_error(ret, "clCreateCommandQueue");
	}
	
	gpu_s0 = clCreateBuffer(ctx, CL_MEM_READ_ONLY, sizeof(s0), NULL, &ret);
	gpu_part2_16bytes = clCreateBuffer(ctx, CL_MEM_READ_ONLY, 16, NULL, &ret);
	gpu_results = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(*results) * total_items, NULL, &ret);
	gpu_item_index = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(uint32_t), NULL, &ret);
	gpu_flags = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(uint32_t), NULL, &ret);
	
	cl_event events[num_devices];
	memset(events, 0, sizeof(cl_event) * num_devices);
	
	app_timer_t timer[1];
	double time_elapsed = 0;
	app_timer_start(timer);
	

	ret = clEnqueueWriteBuffer(queues[0], gpu_s0, CL_TRUE, 0, 32, s0, 0, NULL, NULL);
	cl_check_error(ret, "clEnqueueWriteBuffer");
	
	ret = clEnqueueWriteBuffer(queues[0], gpu_part2_16bytes, CL_TRUE, 0, 16, first_16bytes, 0, NULL, NULL);
	cl_check_error(ret, "clEnqueueWriteBuffer");
	
	time_elapsed = app_timer_stop(timer);
	printf("set input data: time_elapsed=%.3f ms.\n", time_elapsed * 1000.0);
	
	clSetKernelArg(kernel, 0, sizeof(uint32_t), &num_items);
	clSetKernelArg(kernel, 1, sizeof(cl_mem), &gpu_s0);
	clSetKernelArg(kernel, 2, sizeof(cl_mem), &gpu_part2_16bytes);
	clSetKernelArg(kernel, 3, sizeof(cl_mem), &gpu_results);
	clSetKernelArg(kernel, 4, sizeof(cl_mem), &gpu_item_index);
	clSetKernelArg(kernel, 5, sizeof(cl_mem), &gpu_flags);
	
	struct job_context job_ctx = {
		.ctx = ctx,
		.device_id = device_ids[0],
		.gpu_flags = gpu_flags,
	};
	
	pthread_t th;
	int rc = pthread_create(&th, NULL, job_manager_thread, &job_ctx);
	assert(0 == rc);
	
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
	printf("found hash: time_elapsed=%.3f ms.\n", time_elapsed * 1000.0);
	

	for(int i = 0; i < num_devices; ++i) {
		size_t size = sizeof(*results) * NUM_ITEMS;
		size_t offset = sizeof(*results) * num_items * i; 
		ret = clEnqueueReadBuffer(queues[i], gpu_results, CL_TRUE, 
			offset, size,
			(unsigned char *)results + offset, 0, NULL, NULL);
		cl_check_error(ret, "read outputs");
	}
	
	uint32_t item_index = 0;
	ret = clEnqueueReadBuffer(queues[0], gpu_item_index, CL_TRUE, 0, sizeof(uint32_t), &item_index, 
		0, NULL, NULL);
		
	printf("item_index: %u\n", item_index);
	for(int i = 0; i < total_items; ++i) {
		if(results[i].status) {
			printf("found by %d, nonce=%u: ", i, results[i].nonce);
			dump_line("hash: ", results[i].hash, 32);
		}
	}
	
	// verify
	hdr->timestamp = item_index;
	hdr->nonce = results[item_index].nonce;
	
	unsigned char hash[32];
	hash256(hdr, 80, hash);
	printf("hdr: timestamp: %u, nonce: %u\n", hdr->timestamp, hdr->nonce);
	dump_line("gnutls hash: ", hash, 32);
	assert(0 == memcmp(hash, results[item_index].hash, 32));
	
	
	
	for(int i = 0; i < num_devices; ++i) {
		clReleaseCommandQueue(queues[i]);
		clReleaseEvent(events[i]);
	}
	
	
	void * exit_code = NULL;
	s_stop_flags = 1;
	rc = pthread_join(th, &exit_code);
	printf("job_manager thread exited with code %p, rc = %d\n", exit_code, rc);
	
	clReleaseKernel(kernel);
	clReleaseMemObject(gpu_s0);
	clReleaseMemObject(gpu_part2_16bytes);
	clReleaseMemObject(gpu_results);
	clReleaseMemObject(gpu_item_index);
	clReleaseMemObject(gpu_flags);
	
	free(results);
	return;
}
