#ifndef SPV_NODE_H_
#define SPV_NODE_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <json-c/json.h>

#include "satoshi-types.h"
#include "chains.h"
#include "auto_buffer.h"
#include "avl_tree.h"

#include "bitcoin-message.h"

typedef struct spv_node_context spv_node_context_t;
typedef int (* spv_node_message_callback_fn)(struct spv_node_context * spv, const bitcoin_message_t * in_msg);

struct spv_node_context
{
	void * priv;
	void * user_data;
	
	const char * host;
	const char * port;
	
	struct sockaddr_storage addr[1];
	socklen_t addr_len;
	
	pthread_mutex_t mutex;
	pthread_t th;

	uint32_t magic;
	blockchain_t chain[1];
	
	struct pollfd pfd[1];
	int fd;
	
	auto_buffer_t in_buf[1];
	auto_buffer_t out_buf[1];
	
	spv_node_message_callback_fn msg_callbacks[bitcoin_message_types_count];
	
	int argc;
	char ** argv;
	json_object * jconfig;
	int max_retries;
	
	int send_headers_flag;
	avl_tree_t addrs_list[1];
	
};
spv_node_context_t * spv_node_context_init(spv_node_context_t * spv, void * user_data);
void spv_node_context_cleanup(spv_node_context_t * spv);
#define spv_node_lock(spv) 		pthread_mutex_lock(&spv->mutex)
#define spv_node_unlock(spv) 	pthread_mutex_unlock(&spv->mutex)

int spv_node_load_config(spv_node_context_t * spv, json_object * jconfig);
int spv_node_run(spv_node_context_t * spv);

#ifdef __cplusplus
}
#endif
#endif

