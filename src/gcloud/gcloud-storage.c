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

//~ #include "gcloud-storage.h"
#include "gcloud/google-oauth2.h"
#include "utils.h"
#include "json-response.h"

/**
 * Cloud Storage JSON API
 *   https://cloud.google.com/storage/docs/json_api
 * 
 * Reference:
 *   https://cloud.google.com/storage/docs/json_api/v1
**/


struct gcloud_storage_buckets
{
};

struct gcloud_storage_bucket_access_contols
{
};
struct gcloud_storage_object_access_controls
{
};

struct gcloud_storage_objects
{
	CURL * curl;
	
};

typedef struct gcloud_storage_context
{
	google_oauth2_context_t * gauth;
	struct http_json_context http[1];

}gcloud_storage_context_t;


#if defined(_TEST_GCLOUD_STORAGE) && defined(_STAND_ALONE)
/**
 * Cloud Storage JSON API, v1
 * https://developers.google.com/identity/protocols/oauth2/scopes#storage
**/
static const char * g_scope = "https://www.googleapis.com/auth/devstorage.read_write";

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

static char * gcloud_path_uriencode(const char * object_path)
{
	static const char reserved_chars[] = "!#$&'()*+,/:;=?@[] ";
	static size_t num_reserved_chars = sizeof(reserved_chars) - 1;

#define is_reserved_char(c) ({ int is_reserved = 0; \
		for(size_t i = 0; i < num_reserved_chars; ++i) { \
			if((c) == reserved_chars[i]) { is_reserved = 1; break; } \
		}\
		is_reserved; \
	})

	assert(object_path);
	size_t cb_path = strlen(object_path);
	assert(cb_path > 0);
	
	size_t dst_size = cb_path * 3;
	char * dst = calloc(dst_size + 1, 1);
	assert(dst);
	char * p = dst;
	char * p_end = dst + dst_size;

	for(size_t i = 0; i < cb_path; ++i) {
		char c = object_path[i];
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

#define AUTO_FREE_PTR __attribute__((cleanup(auto_free_ptr)))
static void auto_free_ptr(void * ptr) {
	void * p = *(void **)ptr;
	if(p) { free(p); *(void **)ptr = NULL; }
	return;
}

int main(int argc, char **argv)
{
	int rc = 0;
	const char * credentials_file = ".private/credentials.json";
	if(argc > 1) credentials_file = argv[1];
	
	google_oauth2_context_t * gauth = google_oauth2_context_new(NULL);
	rc = gauth->load_credentials_file(gauth, credentials_file);
	gauth->set_scope(gauth, g_scope);
	
	gcloud_storage_context_t gstorage[1];
	memset(gstorage, 0,sizeof(gstorage));
	gstorage->gauth = gauth;
	
	struct http_json_context * http = http_json_context_init(gstorage->http, gstorage);
	assert(http);
	
	
	const char * bucket_name = "storage-tokyo-01";
	char * path = "test_data/01.dat";
	AUTO_FREE_PTR char * encoded_obj_path = NULL;
	encoded_obj_path = gcloud_path_uriencode(path);
	
	printf("encoded_path: %s\n", encoded_obj_path);
	
	static const char * base_url = "https://storage.googleapis.com";
	static const char * list_endpoint = "storage/v1/b";
	static const char * upload_endpoint = "upload/storage/v1/b";
	
	
	static unsigned char test_data[4096] = "test: 123456789\n";
	char url[4096] = "";

	
	json_object * jresponse = NULL;
	AUTO_FREE_PTR char * access_token = NULL;
	ssize_t cb_token = gauth->get_access_token(gauth, &access_token, 0);
	assert(cb_token > 0);
	char auth[4096] = "";
	snprintf(auth, sizeof(auth), "Bearer %s", access_token);
	
	// test 1: list objects
	snprintf(url, sizeof(url), "%s/%s/%s/o", base_url, list_endpoint, bucket_name);
	printf("url: %s\n", url);
	
	http->add_header(http, "Authorization", auth, -1);
	jresponse = http->get(http, url);
	assert(jresponse);
	fprintf(stderr, "response: %s\n", json_object_to_json_string_ext(jresponse, JSON_C_TO_STRING_PRETTY));
	json_object_put(jresponse);
	jresponse = NULL;
	
	// test2. upload files
	snprintf(url, sizeof(url), "%s/%s/%s/o?name=%s&uploadType=media", base_url, upload_endpoint, bucket_name, encoded_obj_path);
	printf("url: %s\n", url);
	http->add_header(http, "Authorization", auth, -1);
	http->add_header(http, "Content-Type", "application/octet-stream", -1);
	http->add_header(http, "Content-Length", "4096", -1);
	jresponse = http->post(http, url, (char *)test_data, 4096);
	
	assert(jresponse);
	fprintf(stderr, "response: %s\n", json_object_to_json_string_ext(jresponse, JSON_C_TO_STRING_PRETTY));
	
	json_object_put(jresponse);
	
	
	google_oauth2_context_free(gauth);
	return rc;
}
#endif

