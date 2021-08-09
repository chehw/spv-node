/*
 * spv-node.c
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
#include <stdint.h>
#include <inttypes.h>

#include <unistd.h>
#include <poll.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>


#include "auto_buffer.h"
#include "chains.h"
#include "utils.h"

#include <pthread.h>
typedef struct spv_node_context
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
	
}spv_node_context_t;
spv_node_context_t * spv_node_context_init(spv_node_context_t * spv, uint32_t magic, void * user_data);
void spv_node_context_cleanup(spv_node_context_t * spv);
#define spv_node_lock(spv) 		pthread_mutex_lock(&spv->mutex)
#define spv_node_unlock(spv) 	pthread_mutex_unlock(&spv->mutex)


#include <poll.h>
static int connect2(const char * host, const char * port, struct sockaddr_storage * p_addr, socklen_t * p_addr_len)
{
	struct addrinfo hints, *serv_info = NULL, *pai;
	int rc = 0;
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	
	rc = getaddrinfo(host, port, &hints, &serv_info);
	if(rc) {
		fprintf(stderr, "[ERROR]: getaddrinfo(%s:%p): %s\n", 
			host, port, 
			gai_strerror(rc));
		exit(1);
	}
	
	int fd = -1;
	char hbuf[NI_MAXHOST] = "";
	char sbuf[NI_MAXSERV] = "";
	
	for(pai = serv_info; pai; pai = pai->ai_next) {
		fd = socket(pai->ai_family, pai->ai_socktype, pai->ai_protocol);
		if(fd < 0) continue;
		
		rc = getnameinfo(pai->ai_addr, pai->ai_addrlen, 
			hbuf, sizeof(hbuf),
			sbuf, sizeof(sbuf),
			NI_NUMERICHOST | NI_NUMERICSERV);
		if(rc) {
			perror("getnameinfo()");
			close(fd);
			fd = -1;
			continue;
		}
		
		fprintf(stderr, "[INFO]: connect to %s:%s ...\n", hbuf, sbuf);
		rc = connect(fd, pai->ai_addr, pai->ai_addrlen);
		if(rc) {
			fprintf(stderr, "    ==> [FAILED]\n");
			close(fd);
			fd = -1;
			continue;
		}
		fprintf(stderr, "    ==> [OK]\n");
		break;
	}
	
	if(NULL == pai) {
		fprintf(stderr, "[ERROR]: connect to [%s:%s] failed.\n", host, port);
		freeaddrinfo(serv_info);
		if(fd >= 0) close(fd);
		return -1;
	}
	
	rc = make_nonblock(fd);
	assert(0 == rc);
	
	if(p_addr) {
		memcpy(p_addr, pai->ai_addr, pai->ai_addrlen);
		*p_addr_len = pai->ai_addrlen;
	}
	return fd;
}

#include <signal.h>
#include <errno.h>
volatile int g_quit = 0;
void on_signal(int sig)
{
	if(sig == SIGINT || sig == SIGUSR1) g_quit = 1;
	
	return;
}

static int on_read(struct pollfd * pfd, void * user_data);
static int on_write(struct pollfd * pfd, void * user_data);

static int add_message_version(spv_node_context_t * spv, int protocol_version);
int main(int argc, char **argv)
{
	signal(SIGINT, on_signal);
	signal(SIGUSR1, on_signal);
	
	int rc = 0;
	const char * default_fullnode = "localhost"; // <<= replace with the fullnode name or ip
	const char * port = "8333";
	
	if(argc > 1) default_fullnode = argv[1];
	if(argc > 2) port = argv[2];
	
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGPIPE);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGINT);

	const struct timespec timeout[1] = {{
		.tv_sec = 0,
		.tv_nsec = 100 * 1000000,
	}};
	
	spv_node_context_t * spv = spv_node_context_init(NULL, 0, NULL);
	assert(spv);
	
	struct pollfd *pfd = spv->pfd;
	memset(pfd, 0, sizeof(*pfd));
	pfd->events = POLLIN | POLLHUP | POLLRDHUP;
	
	spv->host = default_fullnode;
	spv->port = port;

	#define MAX_RETRIES (5)
	for(int retries = 0; retries < MAX_RETRIES; ++retries) 
	{
		int fd = connect2(default_fullnode, port, spv->addr, &spv->addr_len);
		if(fd < 0) {
			fprintf(stderr, "[WARNING]: retries: %d, max_retries: %d\n", retries + 1, MAX_RETRIES);
			sleep(1);
			continue;
		}
		pfd->fd = fd;
		spv->fd = fd;
		
		auto_buffer_cleanup(spv->in_buf);
		auto_buffer_cleanup(spv->out_buf);
		add_message_version(spv, 0);
		pfd->events |= POLLOUT;
		
		while(!g_quit) {
			rc = 0;
			if(spv->out_buf->length > 0) pfd->events |= POLLOUT;
			int n = ppoll(pfd, 1, timeout, &sigs);
			if(n == -1) {
				rc = errno;
				break;
			}
			if(n == 0) // timeout
			{
				if(g_quit || pfd[0].fd < 0) break;
				continue;
			}
			
			if(pfd[0].revents & POLLIN) {
				rc = on_read(pfd, spv);
			}
			if(0 == rc && (pfd[0].revents & POLLOUT)) {
				rc = on_write(pfd, spv);
			}
			printf("rc = %d, revents = %.8x\n", rc, pfd[0].revents);
			
			if(rc < 0 
				|| (pfd[0].revents & POLLERR) 
				|| (pfd[0].revents & POLLHUP)
				|| (pfd[0].revents & POLLRDHUP)
				|| 0)
			{
				fprintf(stderr, "error: rc = %d, revents = 0x%.8x\n", rc, (unsigned int)pfd[0].revents);
				if(pfd[0].fd >= 0) {
					close(pfd[0].fd);
					pfd[0].fd = -1;
				}
				fd = -1;
				spv->fd = -1;
			}
		}
	
	}

	return rc;
}

/**************************************************
 * message handlers
**************************************************/
static int send_message_verack(spv_node_context_t * spv, const struct bitcoin_message * in_msg)
{
	static struct bitcoin_message_header hdr[1] = {{
		.magic = BITCOIN_MESSAGE_MAGIC_MAINNET,
		.command = "verack",
		.length = 0,
		.checksum = 0xe2e0f65d
	}};
	hdr->magic = in_msg->msg_data->magic;
	
	auto_buffer_push(spv->out_buf, hdr, sizeof(*hdr));
	return 0;
}

static int send_message_pong(spv_node_context_t * spv, const struct bitcoin_message * in_msg)
{
	const struct bitcoin_message_header * msg_data = in_msg->msg_data;
	auto_buffer_push(spv->out_buf, msg_data, sizeof(*msg_data) + msg_data->length);
	
	return 0;
}


void bitcoin_message_version_dump(const struct bitcoin_message_version * msg)
{
	printf("==== %s() ====\n", __FUNCTION__);
	printf("version: %d(0x%.8x)\n", msg->version, msg->version);
	printf("service: %"PRIx64"\n", msg->services);
	printf("timestamp: %" PRIi64"\n", msg->timestamp);
	char addr_buf[INET6_ADDRSTRLEN + 1] = "";
	const char * addr = inet_ntop(AF_INET6, msg->addr_recv.ip, addr_buf, sizeof(msg->addr_recv.ip));
	printf("addr_recv: %s:%hu\n", addr, msg->addr_recv.port);
	
	addr = inet_ntop(AF_INET6, msg->addr_from.ip, addr_buf, sizeof(msg->addr_from.ip));
	printf("addr_from: %s:%hu\n", addr, msg->addr_from.port);
	printf("nonce: %ld(%"PRIx64")\n", msg->nonce, msg->nonce);
	
	int cb = varstr_length(msg->user_agent);
	printf("user_agent(cb=%d): %*s\n", cb, cb, varstr_getdata_ptr(msg->user_agent));
	printf("start_height: %d\n", msg->start_height);
	printf("relay: %d\n", msg->relay);
	return;
}

int on_message_handler(spv_node_context_t *spv, const struct bitcoin_message * in_msg)
{
	int rc = 0;
	fprintf(stderr, "[MSG]: type=%s, length=%u\n", 
		bitcoin_message_type_to_string(in_msg->msg_type),
		in_msg->msg_data->length);
	
	switch(in_msg->msg_type)
	{
	case bitcoin_message_type_version:
		bitcoin_message_version_dump(in_msg->priv);
		if(rc) break;
		send_message_verack(spv, in_msg);
		break;
	case bitcoin_message_type_verack:
		break;
	case bitcoin_message_type_ping:
		send_message_pong(spv, in_msg);
		
	default:
		break;
	}
	
	return rc;
}


static int on_read(struct pollfd * pfd, void * user_data)
{
	spv_node_context_t * spv = user_data;
	auto_buffer_t * in_buf = spv->in_buf;
	
	ssize_t length = 0;
	int rc = 0;
	
	struct bitcoin_message msg[1];
	memset(msg, 0, sizeof(msg));
	
	while(0 == rc) {
		char data[4096] = "";
		length = read(pfd->fd, data, sizeof(data));
		if(length <= 0) {
			if(length < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
				fprintf(stderr, "[INFO]: would block\n");
				break;
			}
			perror("read");
			rc = -1;
			break;
		}
		auto_buffer_push(in_buf, data, length);
		if(in_buf->length < sizeof(struct bitcoin_message_header)) continue;
		
		
		const unsigned char * p_start = auto_buffer_get_data(in_buf);
		const unsigned char * p_end = p_start + in_buf->length;
		
		while(p_start < p_end) {
			struct bitcoin_message_header * msg_hdr = (struct bitcoin_message_header * )p_start;
			if((p_start + sizeof(*msg_hdr) + msg_hdr->length) > p_end) break;
			
			bitcoin_message_cleanup(msg);
			rc = bitcoin_message_parse(msg, msg_hdr, msg_hdr->payload, msg_hdr->length);
			if(rc) break;
			
			rc = on_message_handler(spv, msg);
			p_start = msg_hdr->payload + msg_hdr->length;
		}
		
		if(p_start < p_end) memmove(in_buf->data, p_start, p_end - p_start);
		in_buf->start_pos = 0;
		in_buf->length = p_end - p_start;
	}
	
	if(spv->out_buf->length > 0) {
		spv->pfd->events |= POLLOUT;
	}
	
	bitcoin_message_cleanup(msg);
	return rc;
}

static int on_write(struct pollfd * pfd, void * user_data)
{
	assert(pfd && user_data);
	spv_node_context_t * spv = user_data;
	
	int rc = 0;
	ssize_t cb = 0;

	auto_buffer_t * out_buf = spv->out_buf;
	const unsigned char * data = auto_buffer_get_data(out_buf);
	ssize_t length = out_buf->length;
	
	while(length > 0) {
		cb = write(pfd->fd, data, length);
		if(cb <= 0) {
			if(length < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) break;
			
			perror("write");
			rc = -1;
			break;
		}
		data += cb;
		length -= cb;
	}
	
	if(length > 0) {
		memmove(out_buf->data, data, length);
	}
	out_buf->length = length;
	out_buf->start_pos = 0;
	
	if(spv->out_buf->length <= 0) {
		spv->pfd->events &= ~POLLOUT;
	}
	return rc;
}

/**************************************************
 * spv context
**************************************************/
static spv_node_context_t g_spv_node[1] = {{
	.magic = BITCOIN_MESSAGE_MAGIC_MAINNET,
}};

static int add_message_version(spv_node_context_t * spv, int protocol_version)
{
	fprintf(stderr, "==== %s() ====\n", __FUNCTION__);
	struct bitcoin_message_version msg_ver[1];
	memset(msg_ver, 0, sizeof(msg_ver));
	
	struct timespec timestamp = {.tv_sec = 0};
	clock_gettime(CLOCK_REALTIME, &timestamp);
	
	msg_ver->version = protocol_version?protocol_version:70012;
	msg_ver->services = bitcoin_message_service_type_node_network 
		| bitcoin_message_service_type_node_network_limited
		| bitcoin_message_service_type_node_witness
		| 0;
	msg_ver->timestamp = timestamp.tv_sec;
	
	// addr_recv
	msg_ver->addr_recv.services = msg_ver->services;
	
	printf("host: %s\n", spv->host);
	
	if(spv->addr_len == sizeof(struct sockaddr_in6)) {
		memcpy(msg_ver->addr_recv.ip, &((struct sockaddr_in6 *)spv->addr)->sin6_addr, 16);
	}else {
		//~ inet_pton(AF_INET, ctx->host, &msg_ver->addr_recv.ip[12]);
		
		memcpy(&msg_ver->addr_recv.ip[12], &((struct sockaddr_in *)spv->addr)->sin_addr, 16);
		msg_ver->addr_recv.ip[10] = 0xff;
		msg_ver->addr_recv.ip[11] = 0xff;
		
	}
	uint16_t port = atoi(spv->port);
	msg_ver->addr_recv.port = htobe16(port);
	
	msg_ver->nonce = (int64_t)timestamp.tv_sec * 1000000 + timestamp.tv_nsec / 1000;
	static const char * user_agent = "/spv-node:0.1.0(protocol=70012)/";
	ssize_t cb = strlen(user_agent);
	msg_ver->user_agent = varstr_set(NULL, (const unsigned char *)user_agent, cb);
	msg_ver->start_height = 1;
	msg_ver->relay = 1;
	
	auto_buffer_t * out_buf = spv->out_buf;
	unsigned char * payload = NULL;
	cb = bitcoin_message_version_serialize(msg_ver, &payload);
	assert(cb > 0 && payload);
	
	struct bitcoin_message_header hdr[1] = {{
		.magic = spv->magic,
		.command = "version",
	}};
	hdr->length = cb;
	unsigned char hash[32];
	hash256(payload, cb, hash);
	memcpy(&hdr->checksum, hash, 4);
	auto_buffer_push(out_buf, hdr, sizeof(hdr));
	auto_buffer_push(out_buf, payload, cb);
	
	
	dump_line("raw data: ", out_buf->data, out_buf->length);

	dump_line("version: ", &msg_ver->version, 4);
	dump_line("services: ", &msg_ver->services, 8);
	dump_line("timestamp: ", &msg_ver->timestamp, 8);
	dump_line("addr_recv: ", &msg_ver->addr_recv, sizeof(msg_ver->addr_recv));
	dump_line("addr_from: ", &msg_ver->addr_from, sizeof(msg_ver->addr_from));
	dump_line("nonce: ", &msg_ver->nonce, 8);
	dump_line("user_agent: ", msg_ver->user_agent, varstr_size(msg_ver->user_agent));
	dump_line("start_height: ", &msg_ver->start_height, 4);
	dump_line("relay: ", &msg_ver->relay, 1);
	//~ exit(0);
	
	bitcoin_message_version_cleanup(msg_ver);
	return 0;
}

spv_node_context_t * spv_node_context_init(spv_node_context_t * spv, uint32_t magic, void * user_data)
{
	if(NULL == spv) spv = g_spv_node;
	if(magic) spv->magic = magic;
	
	spv->user_data = user_data;
	pthread_mutex_init(&spv->mutex, NULL);
	
	auto_buffer_init(spv->in_buf, 0);
	auto_buffer_init(spv->out_buf, 0);
	
	return spv;
}

void spv_node_context_cleanup(spv_node_context_t * spv)
{
	if(NULL == spv) return;
	auto_buffer_cleanup(spv->in_buf);
	auto_buffer_cleanup(spv->out_buf);
	
	pthread_mutex_destroy(&spv->mutex);
}
