/*
 * gcloud-storage.c
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

#include "gcloud/google-oauth2.h"
#include "utils.h"
#include "json-response.h"

#include "gcloud/gcloud-storage.h"

#define GCLOUD_AUTH_TYPE "Bearer"

/**
 * Cloud Storage JSON API
 *   https://cloud.google.com/storage/docs/json_api
 * 
 * Reference:
 *   https://cloud.google.com/storage/docs/json_api/v1
 * 
 * Cloud Storage JSON API, v1
 *   https://developers.google.com/identity/protocols/oauth2/scopes#storage
**/

/**
 * https://cloud.google.com/storage/docs/request-endpoints#encoding
 * 
 * In addition to general considerations for bucket naming and object naming, 
 * to ensure compatibility across Cloud Storage tools, 
 * you should encode the following characters when they appear in either the object name or query string of a request URI:
 * 
 *  !, #, $, &, ', (, ), *, +, ,, /, :, ;, =, ?, @, [, ], and space characters.
 * 
**/
static char * gcloud_path_uriencode(const char * object_name)
{
	static const char reserved_chars[] = "!#$&'()*+,/:;=?@[] ";
	static size_t num_reserved_chars = sizeof(reserved_chars) - 1;

#define is_reserved_char(c) ({ int is_reserved = 0; \
		for(size_t i = 0; i < num_reserved_chars; ++i) { \
			if((c) == reserved_chars[i]) { is_reserved = 1; break; } \
		}\
		is_reserved; \
	})

	assert(object_name);
	size_t cb_name = strlen(object_name);
	assert(cb_name > 0);
	
	size_t dst_size = cb_name * 3;
	char * dst = calloc(dst_size + 1, 1);
	assert(dst);
	char * p = dst;
	char * p_end = dst + dst_size;

	for(size_t i = 0; i < cb_name; ++i) {
		char c = object_name[i];
		if(is_reserved_char(c)) {
			*p++ = '%';
			p += bin2hex(&c, 1, &p);
		}else {
			*p++ = c;
		}
	}
	assert(p <= p_end);
#undef is_reserved_char
	
	dst_size = p - dst;
	dst = realloc(dst, dst_size + 1);
	dst[dst_size] = '\0';
	return dst;
}


/*************************************************************
 * struct gcloud_storage_objects_interface
*************************************************************/
static json_object * gcloud_storage_objects_list(struct gcloud_storage_context * gstorage, const char * prefix, json_object * jparams);
static json_object * gcloud_storage_objects_get(struct gcloud_storage_context * gstorage, const char * object_name, json_object * jparams);
static ssize_t gcloud_storage_objects_get_media(struct gcloud_storage_context * gstorage, const char * object_name, json_object * jparams, void ** p_data);
static json_object * gcloud_storage_objects_insert(struct gcloud_storage_context * gstorage, const char * object_name, const char * content_type, const void * data, size_t cb_data, json_object * jparams);
static json_object * gcloud_storage_objects_delete(struct gcloud_storage_context * gstorage, const char * object_name, json_object * jparams);
static struct gcloud_storage_objects_interface s_objects_interface_v1 = {
	.list = gcloud_storage_objects_list,
	.get = gcloud_storage_objects_get,
	.get_media = gcloud_storage_objects_get_media,
	.insert = gcloud_storage_objects_insert,
	.delete = gcloud_storage_objects_delete,
};



static ssize_t make_query_string(json_object * jparams, char * query_string, char * p_end)
{
	if(NULL == jparams) return 0;
	assert(query_string && p_end && p_end > query_string);
	
	char *p = query_string;
	struct json_object_iterator iter = json_object_iter_begin(jparams);
	struct json_object_iterator iter_end = json_object_iter_end(jparams);
	while(!json_object_iter_equal(&iter, &iter_end))
	{
		const char * name = json_object_iter_peek_name(&iter);
		assert(name);
		ssize_t cb_name =strlen(name);
		
		json_object * jvalue = json_object_iter_peek_value(&iter);
		enum json_type type = json_object_get_type(jvalue);
		assert(type != json_type_null);
		const char * value = json_object_get_string(jvalue);
		assert(value);
		ssize_t	cb_value = strlen(value);
		
		ssize_t size = cb_name + 1 + cb_value + 1;
		assert((p + size) < p_end); 
		
		if(p > query_string) *p++ = '&';
		ssize_t cb = snprintf(p, p_end - p, "%s=%s", name, value);
		assert(cb > 0);
		p += cb;
		json_object_iter_next(&iter);
	}
	
	ssize_t length = p - query_string;
	assert(length >= 0);
	
	if(length == 0) {
		query_string[0] = '\0';
		return 0;
	}
	return length;
}

static inline void add_gauth_header(struct http_json_context * http, google_oauth2_context_t * gauth)
{
	assert(http && gauth);
	char authorization[PATH_MAX] = GCLOUD_AUTH_TYPE" ";
	char * access_token = authorization + sizeof(GCLOUD_AUTH_TYPE);
	ssize_t cb_token = gauth->get_access_token(gauth, &access_token, 0);
	assert( (cb_token > 0) && (cb_token < (sizeof(authorization) - sizeof(GCLOUD_AUTH_TYPE))) );
	http->add_header(http, "Authorization", authorization, sizeof(GCLOUD_AUTH_TYPE) + cb_token);
	return;
}
	

static json_object * gcloud_storage_objects_list(struct gcloud_storage_context * gstorage, const char * prefix, json_object * jparams)
{
	static const char * end_point = "storage/v1/b";
	char url[PATH_MAX] = "";
	ssize_t cb_url = snprintf(url, sizeof(url), "%s/%s/%s/o", gstorage->base_url, end_point, gstorage->bucket_name);
	assert(cb_url > 0);
	char * query_string = url + cb_url;
	ssize_t cb_query_string = 0;
	
	struct http_json_context * http = gstorage->http;
	http->clear_headers(http);
	add_gauth_header(http, gstorage->gauth);
	
	if(jparams) {
		*query_string++ = '?';
		cb_query_string = make_query_string(jparams, query_string, url + sizeof(url));
		assert(cb_query_string >= 0);
		if(cb_query_string == 0) *--query_string ='\0';
	}

	return http->get(http, url);
}

static json_object * gcloud_storage_objects_get(struct gcloud_storage_context * gstorage, const char * object_name, json_object * jparams)
{
	static const char * end_point = "storage/v1/b";
	assert(object_name);
	
	char * encoded_name = NULL;
	encoded_name = gcloud_path_uriencode(object_name);
	
	char url[PATH_MAX] = "";
	ssize_t cb_url = snprintf(url, sizeof(url), "%s/%s/%s/o/%s", gstorage->base_url, end_point, gstorage->bucket_name, encoded_name);
	assert(cb_url > 0);
	char * query_string = url + cb_url;
	ssize_t cb_query_string = 0;
	free(encoded_name);
	
	struct http_json_context * http = gstorage->http;
	http->clear_headers(http);
	add_gauth_header(http, gstorage->gauth);
	
	if(jparams) {
		*query_string++ = '?';
		cb_query_string = make_query_string(jparams,  query_string, url + sizeof(url));
		assert(cb_query_string >= 0);
		if(cb_query_string == 0) *--query_string ='\0';
	}
	
	return http->get(http, url);
}

static ssize_t gcloud_storage_objects_get_media(struct gcloud_storage_context * gstorage, const char * object_name, json_object * jparams, void ** p_data)
{
	static const char * end_point = "storage/v1/b";
	assert(object_name && p_data);
	
	char * encoded_name = NULL;
	encoded_name = gcloud_path_uriencode(object_name);
	
	char url[PATH_MAX] = "";
	ssize_t cb_url = snprintf(url, sizeof(url), "%s/%s/%s/o/%s?alt=media", gstorage->base_url, end_point, gstorage->bucket_name, encoded_name);
	assert(cb_url > 0);
	char * query_string = url + cb_url;
	ssize_t cb_query_string = 0;
	free(encoded_name);
	
	struct http_json_context * http = gstorage->http;
	struct json_response_context * response = http->response;
	response->auto_parse = 0;
	
	http->clear_headers(http);
	add_gauth_header(http, gstorage->gauth);
	
	if(jparams) {
		*query_string++ = '?';
		cb_query_string = make_query_string(jparams,  query_string, url + sizeof(url));
		assert(cb_query_string >= 0);
		if(cb_query_string == 0) *--query_string ='\0';
	}
	
	http->get(http, url);
	response->auto_parse = 1;
	
	if(response->err_code != 0 || response->response_code < 200 || response->response_code >= 300) return -1;
	
	ssize_t length = response->buf->length;
	if(length > 0) length = auto_buffer_pop(response->buf, (unsigned char **)p_data, length);
	
	return length;
}

static json_object * gcloud_storage_objects_insert(
	struct gcloud_storage_context * gstorage, 
	const char * object_name, 
	const char * upload_type,	// [ "media", "multi-part", "resumable" ]
	const void * data, size_t cb_data, 
	json_object * jparams)
{
	static const char * end_point = "upload/storage/v1/b";
	static const char * content_type = "application/octet-stream";
	
	assert(object_name);
	
	if(NULL == upload_type) upload_type = "media";
	char url[PATH_MAX] = "";
	ssize_t cb_url = snprintf(url, sizeof(url), "%s/%s/%s/o", gstorage->base_url, end_point, gstorage->bucket_name);
	assert(cb_url > 0);
	char * query_string = url + cb_url;
	ssize_t cb_query_string = 0;
	
	struct http_json_context * http = gstorage->http;
	http->clear_headers(http);
	add_gauth_header(http, gstorage->gauth);
	http->add_header(http, "Content-Type", (char *)content_type, -1);
	
	char * encoded_name = NULL;
	encoded_name = gcloud_path_uriencode(object_name);
	
	cb_query_string = snprintf(query_string, 
		sizeof(url) - cb_url, "?name=%s&uploadType=%s",
		encoded_name, upload_type);
	assert(cb_query_string > 0);
	free(encoded_name);
	
	query_string += cb_query_string;
	if(jparams) {
		*query_string++ = '&';
		cb_query_string = make_query_string(jparams,  query_string, url + sizeof(url));
		assert(cb_query_string >= 0);
		if(cb_query_string == 0) *--query_string ='\0';
	}
	
	return http->post(http, url, data, cb_data);
}

static json_object * gcloud_storage_objects_delete(struct gcloud_storage_context * gstorage, const char * object_name, json_object * jparams)
{
	static const char * end_point = "storage/v1/b";
	assert(object_name);
	
	char * encoded_name = NULL;
	encoded_name = gcloud_path_uriencode(object_name);
	
	char url[PATH_MAX] = "";
	ssize_t cb_url = snprintf(url, sizeof(url), "%s/%s/%s/o/%s", gstorage->base_url, end_point, gstorage->bucket_name, encoded_name);
	assert(cb_url > 0);
	char * query_string = url + cb_url;
	ssize_t cb_query_string = 0;
	free(encoded_name);
	
	struct http_json_context * http = gstorage->http;
	http->clear_headers(http);
	add_gauth_header(http, gstorage->gauth);
	
	if(jparams) {
		*query_string++ = '?';
		cb_query_string = make_query_string(jparams,  query_string, url + sizeof(url));
		assert(cb_query_string >= 0);
		if(cb_query_string == 0) *--query_string ='\0';
	}
	return http->delete(http, url, NULL, 0);
}



/*************************************************************
 * struct gcloud_storage_context
*************************************************************/
#define GCLOUD_GSTORAGE_BASE_URL "https://storage.googleapis.com"
gcloud_storage_context_t * gcloud_storage_context_init(gcloud_storage_context_t * gstorage, 
	google_oauth2_context_t * gauth, 
	const char * bucket_name,
	void * user_data)
{
	if(NULL == gstorage) gstorage = calloc(1, sizeof(*gstorage));
	else memset(gstorage, 0, sizeof(*gstorage));
	assert(gstorage && gauth);
	
	// set virtual interfaces
	gstorage->objects = &s_objects_interface_v1;
	
	// set default configurations
	gstorage->base_url = GCLOUD_GSTORAGE_BASE_URL;
	gstorage->gauth = gauth;
	if(bucket_name) strncpy(gstorage->bucket_name, bucket_name, sizeof(gstorage->bucket_name));
	
	// init
	struct http_json_context * http = http_json_context_init(gstorage->http, gstorage);
	assert(http);
	
	return gstorage;
}
void gcloud_storage_context_cleanup(gcloud_storage_context_t * gstorage)
{
	if(NULL == gstorage) return;
	
	http_json_context_cleanup(gstorage->http);
	return;
}


#if defined(_TEST_GCLOUD_STORAGE) && defined(_STAND_ALONE)
static const char * g_scope = "https://www.googleapis.com/auth/devstorage.read_write";
#define dump_json_response(title, jresponse) do { assert(jresponse); \
		fprintf(stderr, "%s: %s\n", title, json_object_to_json_string_ext(jresponse, JSON_C_TO_STRING_PRETTY)); \
		json_object_put(jresponse); \
		jresponse = NULL; \
	} while(0)

int main(int argc, char **argv)
{
	int rc = 0;
	const char * credentials_file = ".private/credentials.json";
	if(argc > 1) credentials_file = argv[1];
	
	const char * bucket_name = "storage-tokyo-01";
	google_oauth2_context_t * gauth = google_oauth2_context_new(NULL);
	rc = gauth->load_credentials_file(gauth, credentials_file);
	gauth->set_scope(gauth, g_scope);
	
	gcloud_storage_context_t * gstorage = gcloud_storage_context_init(NULL, gauth, bucket_name, NULL);
	assert(gstorage);
	
	json_object * jresponse = NULL;
	json_object * jparams = NULL;
	
	// test 1. list objects
	jparams = json_object_new_object();
	json_set_value(jparams, string, delimiter, "/");
	json_set_value(jparams, int, maxResults, 100);
	
	jresponse = gstorage->objects->list(gstorage, NULL, NULL);
	dump_json_response("list objects", jresponse);
	json_object_put(jparams);
	jparams = NULL;
	
	// test2. upload files
	char * object_name = "test_data/02.dat";
	static unsigned char test_data[4096] = "test: 123456789\n";
	
	jresponse = gstorage->objects->insert(gstorage, 
		object_name, NULL, 
		test_data, sizeof(test_data), NULL);
	dump_json_response("upload objects", jresponse);
	json_object_put(jparams);
	jparams = NULL;
	
	// test3. delete files
	object_name = "test_data/02.dat";
	jresponse = gstorage->objects->delete(gstorage, object_name, NULL);
	
	// If successful, this method returns an empty response body.
	if(jresponse) {
		dump_json_response("delete objects failed", jresponse);
	}else {
		fprintf(stderr, "delete objects OK.\n");
	}
	json_object_put(jparams);
	jparams = NULL;
	
	// test4. get files (json-format)
	object_name = "test_data/01.dat";
	jresponse = gstorage->objects->get(gstorage, object_name, NULL);
	dump_json_response("get json objects", jresponse);
	json_object_put(jparams);
	jparams = NULL;
	
	// test4. get media-files (raw data)
	object_name = "test_data/01.dat";
	void * data = NULL;
	ssize_t cb_data = 0;
	cb_data = gstorage->objects->get_media(gstorage, object_name, NULL, &data);
	assert(cb_data >= 0);
	
	if(cb_data > 0) {
		fprintf(stderr, "data file: (length=%ld), data='%.*s'\n", (long)cb_data, (int)cb_data, (char *)data);
	}
	free(data); data = NULL;
	
	gcloud_storage_context_cleanup(gstorage);
	free(gstorage);
	google_oauth2_context_free(gauth);
	return rc;
}
#endif

