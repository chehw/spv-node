#ifndef CHLIB_GOOGLE_OAUTH2_H_
#define CHLIB_GOOGLE_OAUTH2_H_
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <pthread.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <stdint.h>

#include "json-web-token.h"

/**
 * https://developers.google.com/identity/protocols/oauth2/web-server
 * Using OAuth 2.0 for Web Server Applications
**/

struct google_oauth2_web_query_params
{
	// required
	char * client_id;
	char * redirect_uri;		
	char * response_type;
	char * scope;
	
	// recommended
	char * access_type;	// [ "offline", "online" ]
	char * state;
	
	// optional
	_Bool include_granted_scopes;
	char * login_hint;
	char * prompt;
};



/**
 * Using OAuth 2.0 for Server to Server Applications
 * https://developers.google.com/identity/protocols/oauth2/service-account#httprest
**/
//~ struct google_oauth2_jwt_claims
//~ {
	//~ // required
	//~ char * iss; // The email address of the service account.
	//~ char * scope; // A space-delimited list of the permissions that the application requests.
	//~ char * aud; // A descriptor of the intended target of the assertion. When making an access token request this value is always https://oauth2.googleapis.com/token.
	//~ char * exp; // The expiration time of the assertion, specified as seconds since 00:00:00 UTC, January 1, 1970. This value has a maximum of 1 hour after the issued time.
	//~ char * iat; // The time the assertion was issued, specified as seconds since 00:00:00 UTC, January 1, 1970.
	
	//~ // additional
	//~ char * sub;	// The email address of the user for which the application is requesting delegated access.
//~ };

struct google_oauth2_token
{
	json_object * jtoken;
	const char * access_token;
	const char * scope;
	const char * token_type;
	int expires_in;
	
	int64_t iat;
	int64_t exp;
};
void google_oauth2_token_clear(struct google_oauth2_token * auth_token);

typedef struct google_oauth2_context
{
	void * priv;
	void * user_data;
	json_object * jcredentials;
	
	//~ struct google_oauth2_jwt_claims jwt_claims[1];
	json_web_token_t jwt[1];
	struct google_oauth2_token auth_token[1];

	pthread_mutex_t mutex;
	CURL * curl;
	const char * access_token_request_uri;	// default: "https://oauth2.googleapis.com/token"
	const char * grant_type; 	// urlencode("urn:ietf:params:oauth:grant-type:jwt-bearer")
	
	int (* load_credentials_file)(struct google_oauth2_context * gauth, const char * credentials_file);
	int (* set_scope)(struct google_oauth2_context * gauth, const char * scope);
	ssize_t (* get_access_token)(struct google_oauth2_context * gauth, char ** p_token, int force_renewal);
	
}google_oauth2_context_t;
google_oauth2_context_t * google_oauth2_context_init(google_oauth2_context_t * gauth, void * user_data);
void google_oauth2_context_cleanup(google_oauth2_context_t * gauth);
#define google_oauth2_context_new(user_data) google_oauth2_context_init(NULL, user_data)
#define google_oauth2_context_free(gauth) do { if(gauth){ google_oauth2_context_cleanup(gauth); free(gauth);} } while(0)

#ifdef __cplusplus
}
#endif
#endif
