/*
 * opencl-context.c
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

#include "opencl-context.h"

#define CASE_RETURN_STRING(x) case x: return #x;
static inline char * uppercase(char * p)
{
	char c = 0;
	while((c = *p++)) {
		if(c >= 'a' && c <= 'z') p[-1] = (c & ~0x20); 
	}
	return p;
}

const char *cl_strerror(cl_int err)
{
    switch (err)
    {
        CASE_RETURN_STRING(CL_SUCCESS                        )                                  
        CASE_RETURN_STRING(CL_DEVICE_NOT_FOUND               )
        CASE_RETURN_STRING(CL_DEVICE_NOT_AVAILABLE           )
        CASE_RETURN_STRING(CL_COMPILER_NOT_AVAILABLE         ) 
        CASE_RETURN_STRING(CL_MEM_OBJECT_ALLOCATION_FAILURE  )
        CASE_RETURN_STRING(CL_OUT_OF_RESOURCES               )
        CASE_RETURN_STRING(CL_OUT_OF_HOST_MEMORY             )
        CASE_RETURN_STRING(CL_PROFILING_INFO_NOT_AVAILABLE   )
        CASE_RETURN_STRING(CL_MEM_COPY_OVERLAP               )
        CASE_RETURN_STRING(CL_IMAGE_FORMAT_MISMATCH          )
        CASE_RETURN_STRING(CL_IMAGE_FORMAT_NOT_SUPPORTED     )
        CASE_RETURN_STRING(CL_BUILD_PROGRAM_FAILURE          )
        CASE_RETURN_STRING(CL_MAP_FAILURE                    )
        CASE_RETURN_STRING(CL_MISALIGNED_SUB_BUFFER_OFFSET   )
        CASE_RETURN_STRING(CL_COMPILE_PROGRAM_FAILURE        )
        CASE_RETURN_STRING(CL_LINKER_NOT_AVAILABLE           )
        CASE_RETURN_STRING(CL_LINK_PROGRAM_FAILURE           )
        CASE_RETURN_STRING(CL_DEVICE_PARTITION_FAILED        )
        CASE_RETURN_STRING(CL_KERNEL_ARG_INFO_NOT_AVAILABLE  )
        CASE_RETURN_STRING(CL_INVALID_VALUE                  )
        CASE_RETURN_STRING(CL_INVALID_DEVICE_TYPE            )
        CASE_RETURN_STRING(CL_INVALID_PLATFORM               )
        CASE_RETURN_STRING(CL_INVALID_DEVICE                 )
        CASE_RETURN_STRING(CL_INVALID_CONTEXT                )
        CASE_RETURN_STRING(CL_INVALID_QUEUE_PROPERTIES       )
        CASE_RETURN_STRING(CL_INVALID_COMMAND_QUEUE          )
        CASE_RETURN_STRING(CL_INVALID_HOST_PTR               )
        CASE_RETURN_STRING(CL_INVALID_MEM_OBJECT             )
        CASE_RETURN_STRING(CL_INVALID_IMAGE_FORMAT_DESCRIPTOR)
        CASE_RETURN_STRING(CL_INVALID_IMAGE_SIZE             )
        CASE_RETURN_STRING(CL_INVALID_SAMPLER                )
        CASE_RETURN_STRING(CL_INVALID_BINARY                 )
        CASE_RETURN_STRING(CL_INVALID_BUILD_OPTIONS          )
        CASE_RETURN_STRING(CL_INVALID_PROGRAM                )
        CASE_RETURN_STRING(CL_INVALID_PROGRAM_EXECUTABLE     )
        CASE_RETURN_STRING(CL_INVALID_KERNEL_NAME            )
        CASE_RETURN_STRING(CL_INVALID_KERNEL_DEFINITION      )
        CASE_RETURN_STRING(CL_INVALID_KERNEL                 )
        CASE_RETURN_STRING(CL_INVALID_ARG_INDEX              )
        CASE_RETURN_STRING(CL_INVALID_ARG_VALUE              )
        CASE_RETURN_STRING(CL_INVALID_ARG_SIZE               )
        CASE_RETURN_STRING(CL_INVALID_KERNEL_ARGS            )
        CASE_RETURN_STRING(CL_INVALID_WORK_DIMENSION         )
        CASE_RETURN_STRING(CL_INVALID_WORK_GROUP_SIZE        )
        CASE_RETURN_STRING(CL_INVALID_WORK_ITEM_SIZE         )
        CASE_RETURN_STRING(CL_INVALID_GLOBAL_OFFSET          )
        CASE_RETURN_STRING(CL_INVALID_EVENT_WAIT_LIST        )
        CASE_RETURN_STRING(CL_INVALID_EVENT                  )
        CASE_RETURN_STRING(CL_INVALID_OPERATION              )
        CASE_RETURN_STRING(CL_INVALID_GL_OBJECT              )
        CASE_RETURN_STRING(CL_INVALID_BUFFER_SIZE            )
        CASE_RETURN_STRING(CL_INVALID_MIP_LEVEL              )
        CASE_RETURN_STRING(CL_INVALID_GLOBAL_WORK_SIZE       )
        CASE_RETURN_STRING(CL_INVALID_PROPERTY               )
        CASE_RETURN_STRING(CL_INVALID_IMAGE_DESCRIPTOR       )
        CASE_RETURN_STRING(CL_INVALID_COMPILER_OPTIONS       )
        CASE_RETURN_STRING(CL_INVALID_LINKER_OPTIONS         )
        CASE_RETURN_STRING(CL_INVALID_DEVICE_PARTITION_COUNT )
        default: return "Unknown OpenCL error code";
    }
    return NULL;
}

void cl_check_error(cl_int ret, const char * title)
{
	if(ret != CL_SUCCESS) {
		fprintf(stderr, "[ERROR]::%s: %s\n", title, cl_strerror(ret));
		exit(1);
	}
}

/**************************************************
 * struct opencl_platform_info
**************************************************/
void opencl_platform_info_cleanup(struct opencl_platform_info * info)
{
	if(NULL == info) return;
	free(info->profile);
	free(info->version);
	free(info->name);
	free(info->vendor);
	free(info->extensions);
	memset(info, 0, sizeof(*info));
	return;
}
int opencl_platform_info_load(struct opencl_platform_info * info, cl_platform_id platform_id)
{
	assert(info && platform_id);
	info->platform_id = platform_id;
	
	cl_int ret = 0;
	char param_value[4096 + 1] = "";
	size_t cb_param = 0;

	ret = clGetPlatformInfo(platform_id, CL_PLATFORM_PROFILE, sizeof(param_value) - 1, param_value, &cb_param);
	cl_check_error(ret, "clGetPlatformInfo::profile");
	if(cb_param > 0) {
		param_value[cb_param] = '\0';
		info->profile = strdup(param_value);
	}
	
	ret = clGetPlatformInfo(platform_id, CL_PLATFORM_VERSION, sizeof(param_value), param_value, &cb_param);
	cl_check_error(ret, "clGetPlatformInfo::verison");
	if(cb_param > 0) {
		param_value[cb_param] = '\0';
		info->version = strdup(param_value);
	}
	ret = clGetPlatformInfo(platform_id, CL_PLATFORM_NAME, sizeof(param_value), param_value, &cb_param);
	cl_check_error(ret, "clGetPlatformInfo::name");
	if(cb_param > 0) {
		param_value[cb_param] = '\0';
		info->name = strdup(param_value);
	}
	
	ret = clGetPlatformInfo(platform_id, CL_PLATFORM_VENDOR, sizeof(param_value), param_value, &cb_param);
	if(cb_param > 0) {
		param_value[cb_param] = '\0';
		info->vendor = strdup(param_value);
	}
	
	ret = clGetPlatformInfo(platform_id, CL_PLATFORM_EXTENSIONS, sizeof(param_value), param_value, &cb_param);
	cl_check_error(ret, "clGetPlatformInfo::extensions");
	if(cb_param > 0) {
		param_value[cb_param] = '\0';
		info->extensions = strdup(param_value);
	}
	return 0;
}
void opencl_platform_info_dump(const struct opencl_platform_info * info)
{
	assert(info);
	fprintf(stderr, "==== platform: %p ====\n", info->platform_id);
	fprintf(stderr, "profile: %s\n", info->profile);
	fprintf(stderr, "version: %s\n", info->version);
	fprintf(stderr, "name: %s\n", info->name);
	fprintf(stderr, "vendor: %s\n", info->vendor);
	fprintf(stderr, "extensions: %s\n", info->extensions);
	
}

/**************************************************
 * struct opencl_device_info
**************************************************/
#define OPENCL_120_DEVICE_INFO_LAST_ITEM 	CL_DEVICE_PRINTF_BUFFER_SIZE
#define OPENCL_DEVICE_INFO_LAST_ITEM 		OPENCL_120_DEVICE_INFO_LAST_ITEM

static inline size_t query_device_info_item_size(cl_device_info index)
{
	///< @ todo
	
	return 1;
}

int opencl_device_info_load(struct opencl_device_info * info, cl_device_id device_id)
{
	int num_params = OPENCL_DEVICE_INFO_LAST_ITEM - CL_DEVICE_TYPE;
	char param_value[4096 + 1] = "";
	size_t cb_value = 0;
	cl_int ret = 0;
	
	opencl_device_info_cleanup(info);
	
	info->device_id = device_id;
	info->type = 0;
	info->vendor = NULL;
	info->name = NULL;
	
	struct device_param_value * params = calloc(num_params, sizeof(*info->params));
	assert(params);
	info->params = params;
	info->num_params = num_params;

	for(int i = 0; i < num_params; ++i) {
		cb_value = 0;
		ret = clGetDeviceInfo(device_id, CL_DEVICE_TYPE + i, sizeof(param_value) - 1, param_value, &cb_value);
		if(ret != CL_SUCCESS) continue;
		if(cb_value <= 0) continue;
		
		params[i].value = malloc(cb_value);
		memcpy(params[i].value, param_value, cb_value);
		params[i].cb_value = cb_value;
		params[i].item_size = query_device_info_item_size(CL_DEVICE_TYPE + i);
	}
	
	info->type = *(cl_device_type *)params[CL_DEVICE_TYPE - CL_DEVICE_TYPE].value;
	info->vendor = params[CL_DEVICE_VENDOR - CL_DEVICE_TYPE].value;
	info->name = params[CL_DEVICE_NAME - CL_DEVICE_TYPE].value;
	
	uppercase(info->vendor);
	uppercase(info->name);

	return 0;
}

void device_param_value_cleanup(struct device_param_value * param)
{
	if(NULL == param) return;
	if(param->value) free(param->value);
	memset(param, 0, sizeof(*param));
}

void opencl_device_info_cleanup(struct opencl_device_info * info)
{ 
	if(NULL == info) return;
	if(info->params) {
		for(int i = 0; i < info->num_params; ++i) {
			device_param_value_cleanup(&info->params[i]);
		}
		free(info->params);
	}
	memset(info, 0, sizeof(*info));
	return;
}
void opencl_device_info_dump(const struct opencl_device_info * info)
{
	fprintf(stderr, "device_id: %p\n", info->device_id);
	fprintf(stderr, "type: %lu\n", (unsigned long)info->type);
	fprintf(stderr, "vendor: %s\n", info->vendor);
	fprintf(stderr, "device name: %s\n", info->name);
	return;
}



/**************************************************
 * struct opencl_platform_device
**************************************************/
void opencl_platform_device_cleanup(opencl_platform_device_t * device)
{
	if(NULL == device) return;
	for(int i = 0; i < device->num_devices; ++i) {
	//	clReleaseDevice(devices->device_ids[i]);
		opencl_device_info_cleanup(&device->infos[i]);
	}
	free(device->infos);
	memset(device, 0, sizeof(*device));
}


/**************************************************
 * struct opencl_context
**************************************************/
opencl_context_t * opencl_context_init(opencl_context_t * cl, void * user_data)
{
	if(NULL == cl) cl = calloc(1, sizeof(*cl));
	else memset(cl, 0, sizeof(*cl));
	
	cl->user_data = user_data;
	
	cl_uint num_platforms = 0;
	cl_int ret = clGetPlatformIDs(MAX_OPENCL_PLATFORM_IDS, cl->platform_ids, &num_platforms);
	assert(ret == CL_SUCCESS);
	cl->num_platforms = num_platforms;
	
	opencl_platform_device_t * platform_devices = calloc(num_platforms, sizeof(*platform_devices));
	assert(platform_devices);
	cl->platform_devices = platform_devices;
	
	for(int i = 0; i < num_platforms; ++i) {
		cl_platform_id platform_id = cl->platform_ids[i];
		opencl_platform_info_load(&cl->platform_infos[i], platform_id);
		opencl_platform_info_dump(&cl->platform_infos[i]);
		
		opencl_platform_device_t * device = &platform_devices[i];
		
		ret = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_ALL, MAX_OPENCL_DEVICE_IDS, device->device_ids, &device->num_devices);
		if(ret == CL_DEVICE_NOT_FOUND) {
			fprintf(stderr, "[INFO]: no devices found for platform %s(%p)\n", cl->platform_infos[i].name, platform_id);
			continue;
		}
		cl_check_error(ret, "clGetDeviceIDs");
		
		device->platform_id = platform_id;
		if(0 == device->num_devices) continue;
		
		struct opencl_device_info * infos = calloc(device->num_devices, sizeof(*infos));
		assert(infos);
		device->infos = infos;
		for(int ii = 0; ii < device->num_devices; ++ii) {
			opencl_device_info_load(&infos[ii], device->device_ids[ii]);
		}
		
	}
	return cl;
}

void opencl_context_cleanup(opencl_context_t * cl)
{
	if(NULL == cl) return;
	
	for(int i = 0; i < cl->num_platforms; ++i) {
		opencl_platform_info_cleanup(&cl->platform_infos[i]);
	}
	
	if(cl->platform_devices) {
		for(int i = 0; i < cl->num_platforms; ++i) {
			opencl_platform_device_cleanup(&cl->platform_devices[i]);
		}
		free(cl->platform_devices);
		cl->platform_devices = NULL;
	}
	return;
}

static inline ssize_t find_devices(opencl_platform_device_t * device, int type, const char * uppercase_vendor_pattern, cl_device_id * device_ids, struct opencl_device_info ** infos)
{
	assert(device && device->infos && device_ids);
	ssize_t count = 0;

	if(type == 0) type = CL_DEVICE_TYPE_DEFAULT;
	
	for(int i = 0; i < device->num_devices; ++i) {
		struct opencl_device_info * info = &device->infos[i];
		cl_device_id device_id = device->device_ids[i];
		assert(device_id);
	
		if(type != CL_DEVICE_TYPE_ALL) {
			if((info->type & type) == 0) continue;
		}
		
		if(uppercase_vendor_pattern) {
			if(NULL == strstr(info->vendor, uppercase_vendor_pattern)) continue;
		}
		
		if(device_ids) device_ids[count] = device_id; 
		if(infos) infos[count] = info;
		++count;
	}
	return count;
}

ssize_t opencl_get_devices(opencl_context_t * cl, int platform_index, int type, const char * vendor_name_pattern,  cl_device_id ** p_device_ids, struct opencl_device_info *** p_infos)
{
	ssize_t num_devices = 0;
	
	cl_device_id  * device_ids = NULL;
	struct opencl_device_info ** infos = NULL;
	
	if(p_device_ids) {
		device_ids = *p_device_ids;
		if(NULL == device_ids) {
			device_ids = calloc(MAX_OPENCL_DEVICE_IDS, sizeof(*device_ids));
			assert(device_ids);
		}
	}
	
	if(p_infos) {
		infos = *p_infos;
		if(NULL == infos) infos = calloc(MAX_OPENCL_DEVICE_IDS, sizeof(*infos));
		assert(infos);
	}
	
	char * uppercase_pattern = NULL;
	if(vendor_name_pattern) {
		uppercase_pattern = strdup(vendor_name_pattern);
		uppercase(uppercase_pattern);
	}
	
	opencl_platform_device_t * devices = cl->platform_devices;
	if(platform_index >= 0) {
		if(platform_index >= cl->num_platforms) return -1;
		
		num_devices = find_devices(&devices[platform_index], type, uppercase_pattern, 
			device_ids?&device_ids[0]:NULL, 
			infos?&infos[0]:NULL
		);
	}else {
		for(int i = 0; i < cl->num_platforms; ++i) {
			if(devices[i].num_devices == 0) continue;
			ssize_t count = find_devices(&devices[i], type, uppercase_pattern, 
				device_ids?&device_ids[num_devices]:NULL, 
				infos?&infos[num_devices]:NULL
			);
			assert(count >= 0);
			num_devices += count;
			assert(num_devices <= MAX_OPENCL_DEVICE_IDS);
		}
	}
	
	if(num_devices > 0) {
		if(p_device_ids && NULL == *p_device_ids) {
			*p_device_ids = realloc(device_ids, sizeof(*device_ids) * num_devices);
		}
		if(p_infos && NULL == *p_infos) {
			*p_infos = realloc(infos, sizeof(*infos) * num_devices);
		}
	}
	
	if(uppercase_pattern) free(uppercase_pattern);
	return num_devices;
}


#if defined(_TEST_OPENCL_CONTEXT) && defined(_STAND_ALONE)
int main(int argc, char ** argv)
{
	opencl_context_t * cl = opencl_context_init(NULL, NULL);
	int platform_index = -1;
	
	struct opencl_device_info ** infos = NULL;
	ssize_t num_devices = 0;
	
	cl_device_id * device_ids = NULL;
	
	num_devices = opencl_get_devices(cl, platform_index, CL_DEVICE_TYPE_GPU, "nvidia", &device_ids, &infos);
	printf("num_devices: %ld\n", num_devices);
	for(int i = 0; i < num_devices; ++i) {
		assert(device_ids[i] == infos[i]->device_id);
		opencl_device_info_dump(infos[i]);
	}
	
	free(infos);
	free(device_ids);
	
	opencl_context_cleanup(cl);
	free(cl);
	return 0;
}
#endif
