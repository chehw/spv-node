#ifndef OPENCL_CONTEXT_H_
#define OPENCL_CONTEXT_H_

#include <stdio.h>

#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.h>

#ifdef __cplusplus
extern "C" {
#endif

void cl_check_error(cl_int ret, const char * title);
const char *cl_strerror(cl_int err);

#define MAX_OPENCL_PLATFORM_IDS (16)
#define MAX_OPENCL_DEVICE_IDS	(256)
#define MAX_OPENCL_QUEUES		(1024)

struct opencl_platform_info
{
	cl_platform_id platform_id;
	char * profile;
	char * version;
	char * name;
	char * vendor;
	char * extensions;
};
int opencl_platform_info_load(struct opencl_platform_info * info, cl_platform_id platform_id);
void opencl_platform_info_cleanup(struct opencl_platform_info * info);
void opencl_platform_info_dump(const struct opencl_platform_info * info);

struct device_param_value
{
	size_t cb_value;
	size_t item_size;
	char * value;
};
void device_param_value_cleanup(struct device_param_value * param);



struct opencl_device_info
{
	cl_device_id device_id;
	cl_device_type type;
	char * vendor;
	char * name;
	
	int num_params;
	struct device_param_value * params;
};
void opencl_device_info_cleanup(struct opencl_device_info * info);
void opencl_device_info_dump(const struct opencl_device_info * info);


typedef struct opencl_platform_device
{
	cl_platform_id platform_id;
	cl_device_id device_ids[MAX_OPENCL_DEVICE_IDS];
	
	cl_uint num_devices;
	struct opencl_device_info * infos;
}opencl_platform_device_t;
int opencl_device_info_load(struct opencl_device_info * info, cl_device_id device_id);
void opencl_platform_device_cleanup(opencl_platform_device_t * device);


typedef struct opencl_context
{
	void * user_data;
	
	cl_platform_id platform_ids[MAX_OPENCL_PLATFORM_IDS];
	struct opencl_platform_info	platform_infos[MAX_OPENCL_PLATFORM_IDS];
	
	cl_uint num_platforms;
	opencl_platform_device_t * platform_devices;
}opencl_context_t;
opencl_context_t * opencl_context_init(opencl_context_t * cl, void * user_data);
void opencl_context_cleanup(opencl_context_t * cl);
ssize_t opencl_get_devices(opencl_context_t * cl, int platform_index, int type, const char * vendor_name_pattern,  cl_device_id ** p_device_ids, struct opencl_device_info *** p_infos);

#define opencl_context_new(user_data) opencl_context_init(NULL, user_data)
#define opencl_context_free(cl) do { if(cl) { opencl_context_cleanup(cl); free(cl); } } while(0)

#ifdef __cplusplus
}
#endif
#endif
