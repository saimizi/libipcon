#include <stdio.h>
#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <jslist.h>

#include "libipcon.h"

#define ipcon_dbg(fmt, ...) \
	fprintf(stderr, "[ipcon_server] Debug: "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[ipcon_server] Info: "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[ipcon_server] Error: "fmt, ##__VA_ARGS__)

#define PEER_NAME	"ipcon_server"
#define GRP_NAME	"StrMsgServer"

#define SYNC_GRP_MSG	1
#define ASYNC_GRP_MSG	0

struct gs_event {
	struct list_node node;
	struct ipcon_msg msg;
};

pthread_t group_sender_id;
sem_t sem_group_sender;
pthread_mutex_t mutex_group_sender;
struct list_node_head gs_event_qeue;


void gs_lock() {
	pthread_mutex_lock(&mutex_group_sender);
}

void gs_unlock() {
	pthread_mutex_unlock(&mutex_group_sender);
}

char gs_buf[IPCON_MAX_NAME_LEN + IPCON_MAX_MSG_LEN + 16];
void * group_sender(void *para)
{
	IPCON_HANDLER handler = (IPCON_HANDLER)para;

	while (1) {
		struct gs_event *ge = NULL;
		struct list_node_head local_event_queue;

		sem_wait(&sem_group_sender);
		gs_lock();
		list_init_head(&local_event_queue);
		list_move(&gs_event_qeue, &local_event_queue);
		gs_unlock();

		struct list_node *it;
		while (ge = LIST_POP(&local_event_queue,
				struct gs_event, node, it)) {

			if (ge->msg.type == IPCON_MSG_UNICAST) {
				ipcon_info("IPCON_MSG_UNICAST \n");
				sprintf(gs_buf, "%s : %s\n", ge->msg.peer, ge->msg.buf);
			} else {
				ipcon_info("IPCON_GROUP_MSG : %s\n", ge->msg.group);

				if (strcmp(ge->msg.group, IPCON_KERNEL_GROUP)) {
					free(ge);
					continue;
				}

				struct ipcon_kevent * ik;
				ik = (struct ipcon_kevent *)ge->msg.buf;

				switch (ik->type) {
				case IPCON_EVENT_PEER_ADD:
					sprintf(gs_buf, "%s : peer %s added\n",
						IPCON_KERNEL_GROUP,
						ik->peer.name);
					break;

				case IPCON_EVENT_PEER_REMOVE:
					sprintf(gs_buf, "%s : peer %s removed\n",
						IPCON_KERNEL_GROUP,
						ik->peer.name);
					break;

				case IPCON_EVENT_GRP_ADD:
					sprintf(gs_buf, "%s : group %s of peer %s added\n",
						IPCON_KERNEL_GROUP,
						ik->group.name,
						ik->group.peer_name);
					break;

				case IPCON_EVENT_GRP_REMOVE:
					sprintf(gs_buf, "%s : group %s of peer %s removed\n",
						IPCON_KERNEL_GROUP,
						ik->group.name,
						ik->group.peer_name);
					break;

				default:
					break;
				}
			}

			ipcon_info("%s\n", gs_buf);
			ipcon_send_multicast(handler,
					GRP_NAME,
					gs_buf,
					strlen(gs_buf) + 1,
					SYNC_GRP_MSG);
			free(ge);
		}
	}

	return NULL;
}


int main(int argc, char *argv[])
{

	int ret = 0;
	IPCON_HANDLER	handler;
	int should_quit = 0;

	handler = ipcon_create_handler(PEER_NAME, SERVICE_PUBLISHER);
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {
		ret = ipcon_join_group(handler, IPCON_NAME,
				IPCON_KERNEL_GROUP);
		if (ret < 0) {
			ipcon_err("Failed to join %s group :%s(%d).\n",
					IPCON_KERNEL_GROUP,
					strerror(-ret),
					-ret);
			ret = 1;
			break;
		}

		ipcon_info("Joined %s group.\n", IPCON_KERNEL_GROUP);
		ret = ipcon_register_group(handler, GRP_NAME);
		if (ret < 0) {
			ipcon_err("Failed to register group: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}

		ipcon_info("Register group %s succeed.\n", GRP_NAME);

		list_init_head(&gs_event_qeue);
		pthread_mutex_init(&mutex_group_sender, NULL);
		sem_init(&sem_group_sender, 0, 0);

		ret = pthread_create(&group_sender_id,
					NULL,
					group_sender,
					(void *)handler);


		while (!should_quit) {
			struct ipcon_msg im;
			struct gs_event *ge = NULL;

			memset(&im, 0, sizeof(im));
			ret = ipcon_rcv(handler, &im);
			if (ret < 0) {
				ipcon_err("Rcv mesg failed: %s(%d).\n",
					strerror(-ret), -ret);
				continue;
			}

			ge = (struct gs_event *)malloc(sizeof (*ge));
			list_init_node(&ge->node);
			memcpy(&ge->msg, &im, sizeof(im));

			gs_lock();
			list_append(&gs_event_qeue, &ge->node);
			sem_post(&sem_group_sender);
			gs_unlock();

		}

		ret = ipcon_unregister_group(handler, GRP_NAME);
		if (ret < 0) {
			ipcon_err("Failed to unregister group: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}
		ipcon_info("Unregister group %s succeed.\n", GRP_NAME);

	} while (0);

	ipcon_free_handler(handler);

	return ret;
}
