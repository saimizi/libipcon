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

#define srv_name	"ipcon_server"
#define grp_name	"str_msg"
__u32 sender_port;

static void ipcon_kevent(struct ipcon_msg *im)
{
	struct ipcon_kevent *ik;

	if (!im)
		return;

	ik = (struct ipcon_kevent *)im->buf;

	switch (ik->type) {
	case IPCON_EVENT_PEER_REMOVE:
		if (ik->peer.portid == sender_port) {
			sender_port = 0;
			ipcon_info("Detected sender@%lu removed.\n",
				 (unsigned long)ik->peer.portid);
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
				im->port,
				"bye",
				strlen("bye") + 1);

		if (sender_port && (im->port != sender_port))
			ipcon_send_unicast(handler,
				sender_port,
				"bye",
				strlen("bye") + 1);

		ipcon_send_multicast(handler, grp_name,
				"bye",
				strlen("bye") + 1);


		return ret;
	}

	if (!sender_port)
		return 0;

	if (im->port == sender_port) {
		ipcon_info("Msg from sender %lu: %s. size=%d.\n",
				(unsigned long)im->port, im->buf, (int)im->len);

		ret = ipcon_send_unicast(handler,
				im->port,
				"OK",
				strlen("OK") + 1);

		ret = ipcon_send_multicast(handler, grp_name, im->buf, im->len);
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

	handler = ipcon_create_handler();
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {
		ret = ipcon_join_group(handler, IPCON_KERNEL_GROUP_NAME, 0);
		if (ret < 0) {
			ipcon_err("Failed to join %s group :%s(%d).\n",
					IPCON_KERNEL_GROUP_NAME,
					strerror(-ret),
					-ret);
			ret = 1;
			break;
		}

		ipcon_info("Joined %s group.\n", IPCON_KERNEL_GROUP_NAME);

		ret = ipcon_register_service(handler, srv_name);
		if (ret < 0) {
			ipcon_err("Failed to register service: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}

		ipcon_info("Register service %s succeed.\n", srv_name);

		ret = ipcon_register_group(handler, grp_name);
		if (ret < 0) {
			ipcon_err("Failed to register group: %s (%d)\n",
					strerror(-ret), -ret);
			ipcon_unregister_service(handler, srv_name);
			break;
		}

		ipcon_info("Register group %s succeed.\n", grp_name);

		while (!should_quit) {
			struct ipcon_msg im;

			ret = ipcon_rcv(handler, &im);
			if (ret < 0) {
				ipcon_err("Rcv mesg failed: %s(%d).\n",
					strerror(-ret), -ret);
				continue;
			}

			if (im.type == IPCON_NORMAL_MSG)  {
				if (!sender_port)
					sender_port = im.port;

				if (!strcmp(im.buf, "bye"))
					should_quit = 1;

				normal_msg_handler(handler, &im);

			} else if (im.type == IPCON_GROUP_MSG) {
				if (!strcmp(im.group, IPCON_KERNEL_GROUP_NAME))
					ipcon_kevent(&im);

			} else {
				ipcon_err("Invalid message type (%lu).\n",
					(unsigned long)im.type);
			}
		}

		ret = ipcon_unregister_service(handler, srv_name);
		if (ret < 0) {
			ipcon_err("Failed to unregister service: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}
		ipcon_info("Unregister service %s succeed.\n", srv_name);

		ret = ipcon_unregister_group(handler, grp_name);
		if (ret < 0) {
			ipcon_err("Failed to unregister group: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}
		ipcon_info("Unregister group %s succeed.\n", grp_name);

	} while (0);

	ret = ipcon_free_handler(handler);

	return ret;
}
