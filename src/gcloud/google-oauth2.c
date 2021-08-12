/*
 * google-oauth2.c
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

#include <stdbool.h>
#include <json-c/json.h>
#include <curl/curl.h>
#include <time.h>

#include "json-web-token.h"
#include "auto_buffer.h"
#include "gcloud/google-oauth2.h"
#include "utils.h"

static const char s_oauth2_request_uri[] = "https://oauth2.googleapis.com/token";
static const char s_oauth2_grant_type[] = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";

static const char s_oauth2_alg[] = "RS256";
static const char s_oauth2_typ[] = "JWT";
static const char s_oauth2_jwt_aud[] = "https://oauth2.googleapis.com/token";

static int google_oauth2_load_credentials_file(struct google_oauth2_context * gauth, const char * credentials_file);
static int google_oauth2_set_scope(struct google_oauth2_context * gauth, const char * scope);
static ssize_t google_oauth2_get_access_token(struct google_oauth2_context * gauth, char ** p_token, int force_renewal);
google_oauth2_context_t * google_oauth2_context_init(google_oauth2_context_t * gauth, void * user_data)
{
	if(NULL == gauth) gauth = calloc(1, sizeof(*gauth));
	else memset(gauth, 0, sizeof(*gauth));
	
	pthread_mutex_init(&gauth->mutex, NULL);
	gauth->user_data = user_data;
	gauth->load_credentials_file	= google_oauth2_load_credentials_file;
	gauth->set_scope = google_oauth2_set_scope;
	gauth->get_access_token = google_oauth2_get_access_token;
	
	gauth->access_token_request_uri = s_oauth2_request_uri;
	gauth->grant_type = s_oauth2_grant_type;
	
	json_web_token_t * jwt = json_web_token_init(gauth->jwt, gauth);
	assert(jwt && jwt == gauth->jwt);
	jwt->alg = s_oauth2_alg;
	jwt->typ = s_oauth2_typ;
	
	jwt->add_claims(jwt, "aud", s_oauth2_jwt_aud, NULL);

	CURL * curl = curl_easy_init();
	assert(curl);
	gauth->curl = curl;
	
	return gauth;
}

void google_oauth2_token_clear(struct google_oauth2_token * auth_token)
{
	if(NULL == auth_token) return;
	if(auth_token->jtoken) {
		json_object_put(auth_token->jtoken);
		auth_token->jtoken = NULL;
	}
	memset(auth_token, 0, sizeof(*auth_token));
	return;
}

void google_oauth2_context_cleanup(google_oauth2_context_t * gauth)
{
	if(NULL == gauth) return;
	
	if(gauth->curl) {
		curl_easy_cleanup(gauth->curl);
		gauth->curl = NULL;
	}
	
	json_web_token_cleanup(gauth->jwt);
	google_oauth2_token_clear(gauth->auth_token);
	
	if(gauth->jcredentials) {
		json_object_put(gauth->jcredentials);
		gauth->jcredentials = NULL;
	}
	
	return;
}


static int google_oauth2_load_credentials_file(struct google_oauth2_context * gauth, const char * credentials_file)
{
	assert(gauth && credentials_file);
	int rc = 0;
	
	
	json_object * jcredentials = json_object_from_file(credentials_file);
	assert(jcredentials);
	//~ const char * project_id = json_get_value(jcredentials, string, project_id);
	//~ const char * private_key_id = json_get_value(jcredentials, string, private_key_id);
	const char * private_key = json_get_value(jcredentials, string, private_key);
	const char * client_email = json_get_value(jcredentials, string, client_email);
	//~ const char * client_id = json_get_value(jcredentials, string, client_id);
	//~ const char * auth_uri = json_get_value(jcredentials, string, auth_uri);
	const char * token_uri = json_get_value(jcredentials, string, token_uri);
	//~ const char * auth_provider_x509_cert_url = json_get_value(jcredentials, string, auth_provider_x509_cert_url);
	//~ const char * client_x509_cert_url = json_get_value(jcredentials, string, client_x509_cert_url);
	
	if(token_uri) gauth->access_token_request_uri = token_uri;
	
	assert(private_key && client_email);
	json_web_token_t * jwt = gauth->jwt;
	assert(jwt && jwt->add_claims && jwt->set_privkey);
	
	rc = jwt->set_privkey(jwt, private_key, strlen(private_key));	assert(0 == rc);
	rc = jwt->add_claims(jwt, "iss", client_email, NULL); 			assert(0 == rc);
	
	google_oauth2_token_clear(gauth->auth_token);
	gauth->jcredentials = jcredentials;
	
	return 0;
}
static int google_oauth2_set_scope(struct google_oauth2_context * gauth, const char * scope)
{
	assert(gauth);
	int rc = 0;
	json_web_token_t * jwt = gauth->jwt;
	assert(jwt && jwt->add_claims);
	rc = jwt->add_claims(jwt, "scope", scope, NULL);
	return rc;
}

static size_t on_http_response(char * data, size_t size, size_t n, void * user_data)
{
	auto_buffer_t * buf = user_data;
	size_t cb = size * n;
	if(cb == 0) return 0;
	
	int rc = auto_buffer_push(buf, data, cb);
	if(rc) return 0;
	
	return cb;
}

static int google_oauth2_request_token(struct google_oauth2_context * gauth, const struct timespec * timestamp)
{
	assert(gauth && gauth->curl);
	assert(gauth->access_token_request_uri);
	
	json_web_token_t * jwt = gauth->jwt;
	struct google_oauth2_token * auth_token = gauth->auth_token;
	google_oauth2_token_clear(auth_token);
	
	struct timespec ts[1];
	if(NULL == timestamp) {
		memset(ts, 0, sizeof(ts));
		clock_gettime(CLOCK_REALTIME, ts);
		timestamp = ts;
	}

	// generate and sign jwt
	char issued_at[32] = "";
	char expires_at[32] = "";
	static const int expires = 3600;	// 1 hour
	
	auth_token->iat = timestamp->tv_sec;
	auth_token->exp = auth_token->iat + expires;
	
	snprintf(issued_at, sizeof(issued_at), "%ld", (long)auth_token->iat);
	snprintf(expires_at, sizeof(expires_at), "%ld", (long)auth_token->exp);
	
	jwt->add_claims(jwt, "iat", issued_at, "exp", expires_at, NULL);
	jwt->sign(jwt);
	const char * assertion = jwt->b64_data;	// signed jwt token

	int rc = -1;
	auto_buffer_t in_buf[1];
	auto_buffer_t out_buf[1];
	auto_buffer_init(in_buf, 4096);
	auto_buffer_init(out_buf, 0);
	
	ssize_t cb = snprintf((char *)in_buf->data, in_buf->size, 
		"grant_type=%s&"
		"assertion=%s", 
		gauth->grant_type, 
		//~ "urn:ietf:params:oauth:grant-type:jwt-bearer",
		assertion);
	assert(cb >= 0 && cb < in_buf->size);
	in_buf->length = cb;
	
	printf("post_fields: %s\n", (char *)in_buf->data);
	
	
	CURL * curl = gauth->curl;
	curl_easy_setopt(curl, CURLOPT_URL, gauth->access_token_request_uri);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_http_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, out_buf);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, in_buf->data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, in_buf->length);
	
	//~ struct curl_slist * headers = NULL;
	//~ headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
	//~ curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	CURLcode ret = curl_easy_perform(curl);
	//~ curl_slist_free_all(headers);
	rc = -1;
	if(ret == CURLE_OK) {
		auto_buffer_resize(out_buf, out_buf->length + 1);
		out_buf->data[out_buf->length] = '\0';
		long response_code = 0;
		ret = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		
		debug_printf("response_code: %ld\nresponse: %s", response_code, (char *)out_buf->data);
		
		if(ret == CURLE_OK && (response_code >= 200 && response_code < 300)) {
			
			json_tokener * jtok = json_tokener_new();
			enum json_tokener_error jerr = json_tokener_error_parse_null;
			json_object * jtoken = json_tokener_parse_ex(jtok, (char *)out_buf->data, out_buf->length);
			jerr = json_tokener_get_error(jtok);
			if(jerr == json_tokener_success) {
				
				auth_token->jtoken = jtoken;
				auth_token->access_token = json_get_value(jtoken, string, access_token);
				auth_token->scope = json_get_value(jtoken, string, scope);
				auth_token->token_type = json_get_value(jtoken, string, token_type);
				auth_token->expires_in = json_get_value(jtoken, int, expires_in);
				
				if(auth_token->expires_in > 0) auth_token->exp = auth_token->iat + auth_token->expires_in;
				rc = 0;
			}else {
				if(jtoken) json_object_put(jtoken);
			}
			json_tokener_free(jtok);
		}
	}else {
		fprintf(stderr, "[ERROR]: %s(): %s\n", __FUNCTION__, curl_easy_strerror(ret));
	}
	
	auto_buffer_cleanup(in_buf);
	auto_buffer_cleanup(out_buf);
	return rc;
}


static ssize_t google_oauth2_get_access_token(struct google_oauth2_context * gauth, char ** p_token, int force_renewal)
{
	int rc = 0;
	ssize_t cb_token = -1;
	
	struct timespec timestamp[1];
	memset(timestamp, 0, sizeof(timestamp));
	clock_gettime(CLOCK_REALTIME, timestamp);
	
	struct google_oauth2_token * auth_token = gauth->auth_token;
	if(force_renewal || (auth_token->exp <= timestamp->tv_sec)) {
		
		auth_token->iat = timestamp->tv_sec;
		rc = google_oauth2_request_token(gauth, timestamp);
	}
	
	if(0 == rc) {
		assert(auth_token->access_token);
		cb_token = strlen(auth_token->access_token);
		assert(cb_token > 0);
		if(NULL == p_token) return cb_token + 1;
		
		char * token = *p_token;
		if(NULL == token) {
			token = calloc(cb_token + 1, 1);
			assert(token);
			*p_token = token;
		}
		memcpy(token, auth_token->access_token, cb_token);
	}
	return cb_token;
}


#if defined(_TEST_GOOGLE_OAUTH2) && defined(_STAND_ALONE)

/**
 * Cloud Storage JSON API, v1
 * https://developers.google.com/identity/protocols/oauth2/scopes#storage
**/
static const char * g_scope = "https://www.googleapis.com/auth/devstorage.read_write";

int main(int argc, char **argv)
{
	int rc = 0;
	const char * credentials_file = ".private/credentials.json";
	if(argc > 1) credentials_file = argv[1];
	
	google_oauth2_context_t * gauth = google_oauth2_context_new(NULL);

	rc = gauth->load_credentials_file(gauth, credentials_file);
	gauth->set_scope(gauth, g_scope);
	
	assert(0 == rc);

	char * access_token = NULL;
	ssize_t cb_token = gauth->get_access_token(gauth, &access_token, FALSE);
	assert(cb_token >0);
	
	printf("cb_token: %ld\n token* %s\n", (long)cb_token, access_token);
	
	free(access_token);
	access_token = NULL;
	google_oauth2_context_free(gauth);
	return 0;
}
#endif

