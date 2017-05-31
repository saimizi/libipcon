#include <stdio.h>
#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "libipcon.h"

#define ipcon_dbg(fmt, ...) \
	fprintf(stderr, "[ipcon_server] Debug: "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[ipcon_server] Info: "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[ipcon_server] Error: "fmt, ##__VA_ARGS__)

#define PEER_NAME	"ipcon_server"
#define GRP_NAME	"str_msg"

char *src_peer;

static void ipcon_kevent(struct ipcon_msg *im)
{
	struct ipcon_kevent *ik;

	if (!im)
		return;

	ik = (struct ipcon_kevent *)im->buf;

	switch (ik->type) {
	case IPCON_EVENT_PEER_REMOVE:
		if (!strcmp(ik->peer.name, src_peer)) {
			ipcon_info("Detected %s@%lu removed.\n",
				 ik->peer.name,
				 (unsigned long)ik->peer.port);

			free(src_peer);
			src_peer = NULL;
		}
		break;
	default:
		break;
	}
}

static int normal_msg_handler(IPCON_HANDLER handler, struct ipcon_msg *im)
{
	int ret = 0;

	if (!handler || !im)
		return -EINVAL;

	if (!strcmp(im->buf, "bye")) {
		ipcon_send_unicast(handler,
				im->peer,
				"bye",
				strlen("bye") + 1);

		if (src_peer && strcmp(im->peer, src_peer))
			ipcon_send_unicast(handler,
				src_peer,
				"bye",
				strlen("bye") + 1);

		ipcon_send_multicast(handler, GRP_NAME,
				"bye",
				strlen("bye") + 1);


		return ret;
	}

	if (!src_peer)
		return 0;

	if (!strcmp(im->peer, src_peer)) {
		ipcon_info("Msg from sender %s: %s. size=%d.\n",
				im->peer, im->buf, (int)im->len);

		ret = ipcon_send_unicast(handler,
				im->peer,
				"OK",
				strlen("OK") + 1);

		ret = ipcon_send_multicast(handler, GRP_NAME, im->buf, im->len);
		if (ret < 0)
			ipcon_err("Failed to send mutlcast message:%s(%d).",
				strerror(-ret), -ret);
	}

	return ret;
}

int main(int argc, char *argv[])
{

	int ret = 0;
	IPCON_HANDLER	handler;
	int should_quit = 0;

	handler = ipcon_create_handler(PEER_NAME);
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {
		ret = ipcon_join_group(handler, IPCON_GENL_NAME,
				IPCON_KERNEL_GROUP, 0);
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

		while (!should_quit) {
			struct ipcon_msg im;

			ret = ipcon_rcv(handler, &im);
			if (ret < 0) {
				ipcon_err("Rcv mesg failed: %s(%d).\n",
					strerror(-ret), -ret);
				continue;
			}

			if (im.type == IPCON_NORMAL_MSG)  {
				if (!src_peer)
					src_peer = strdup(im.peer);

				if (!strcmp(im.buf, "bye"))
					should_quit = 1;

				normal_msg_handler(handler, &im);

			} else if (im.type == IPCON_GROUP_MSG) {
				if (!strcmp(im.group, IPCON_KERNEL_GROUP))
					ipcon_kevent(&im);

			} else {
				ipcon_err("Invalid message type (%lu).\n",
					(unsigned long)im.type);
			}
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
