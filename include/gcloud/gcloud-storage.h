#ifndef CHLIB_GCLOUD_STORAGE_H_
#define CHLIB_GCLOUD_STORAGE_H_
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <pthread.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <stdint.h>

#include "google-oauth2.h"
#include "json-response.h"

struct gcloud_storage_context;
struct gcloud_storage_buckets_interface
{
	
};

struct gcloud_storage_bucket_access_contols_interface
{
	
};

struct gcloud_storage_object_access_controls_interface
{
	
};

struct gcloud_storage_objects_interface
{
	json_object * (* list)(struct gcloud_storage_context * gstorage, const char * prefix, json_object * jparams);
	json_object * (* get)(struct gcloud_storage_context * gstorage, const char * object_name, json_object * jparams);
	ssize_t (* get_media)(struct gcloud_storage_context * gstorage, const char * object_name, json_object * jparams, void ** p_data);
	
	json_object * (* insert)(struct gcloud_storage_context * gstorage, 
		const char * object_name, const char * upload_type,	// [ "media", "multi-part", "resumable" ]
		const void * data, size_t cb_data, // payload
		json_object * jparams);
	json_object * (* delete)(struct gcloud_storage_context * gstorage, const char * object_name, json_object * jparams);
};

typedef struct gcloud_storage_context
{
	struct http_json_context http[1];
	google_oauth2_context_t * gauth;
	const char * base_url;
	
	char bucket_name[PATH_MAX];
	struct gcloud_storage_objects_interface * objects;
}gcloud_storage_context_t;

gcloud_storage_context_t * gcloud_storage_context_init(gcloud_storage_context_t * gstorage, 
	google_oauth2_context_t * gauth, 
	const char * bucket_name,
	void * user_data);
void gcloud_storage_context_cleanup(gcloud_storage_context_t * gstorage);

#ifdef __cplusplus
}
#endif
#endif


