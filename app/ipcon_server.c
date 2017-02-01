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
__u32 sender_port;

static void ipcon_kevent(struct ipcon_kevent *ik)
{
	if (!ik)
		return;

	switch (ik->type) {
	case IPCON_EVENT_PEER_REMOVE:
		if (ik->peer.portid == sender_port) {
			sender_port = 0;
			ipcon_info("Sender@%lu is detected to be removed.\n",
				 (unsigned long)ik->peer.portid);
		}
		break;
	default:
		break;
	}
}

static int normal_msg_handler(IPCON_HANDLER handler, __u32 port, void *buf,
				size_t len)
{
	int ret = 0;

	if (!buf)
		return -EINVAL;

	if (!sender_port)
		return 0;

	if (port == sender_port) {
		ipcon_info("Msg from sender %lu: %s. size=%d.\n",
				(unsigned long)port, (char *)buf, (int)len);

		ret = ipcon_send_unicast(handler,
				port,
				"OK",
				strlen("OK") + 1);
	}

	return ret;
}

int main(int argc, char *argv[])
{

	int ret = 0;
	IPCON_HANDLER	handler;
	int should_quit = 0;
	int ipcon_kevent_group = 0;

	handler = ipcon_create_handler();
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {
		ipcon_kevent_group = ipcon_join_group(handler,
					IPCON_KERNEL_GROUP_NAME, 0);
		if (ipcon_kevent_group < 0)
			ipcon_err("Failed to get %s group :%s(%d).\n",
					IPCON_KERNEL_GROUP_NAME,
					strerror(-ipcon_kevent_group),
					-ipcon_kevent_group);
		else
			ipcon_info("Joined %s group (groupid = %d).\n",
					IPCON_KERNEL_GROUP_NAME,
					ipcon_kevent_group);

		ret = ipcon_register_service(handler, srv_name);
		if (ret < 0) {
			ipcon_err("Failed to register service: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}

		ipcon_info("Register service %s succeed.\n", srv_name);

		while (!should_quit) {
			int len = 0;
			void *buf = NULL;
			__u32 port;
			__u32 group;
			__u32 type = 0;

			len = ipcon_rcv(handler, &port, &group, &type, &buf);
			if (len < 0) {
				ipcon_err("Rcv mesg failed: %s(%d).\n",
					strerror(-len), -len);
				continue;
			}

			if (type == IPCON_NORMAL_MSG)  {
				if (!sender_port)
					sender_port = port;

				if (!strcmp(buf, "bye")) {
					should_quit = 1;

					ipcon_send_unicast(handler,
						port,
						"bye",
						strlen("bye") + 1);

					if (sender_port &&
						(sender_port != port))
						ipcon_send_unicast(handler,
							sender_port,
							"bye",
							strlen("bye") + 1);
					free(buf);
					continue;
				}

				normal_msg_handler(handler, port, buf, len);

			} else if (type == IPCON_GROUP_MSG) {
				if (group == ipcon_kevent_group)
					ipcon_kevent(buf);

			} else {
				ipcon_err("Invalid message type (%lu).\n",
					(unsigned long)type);
			}

			free(buf);

		}

		ret = ipcon_unregister_service(handler, srv_name);
		if (ret < 0) {
			ipcon_err("Failed to unregister service: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}
		ipcon_info("Unregister service %s succeed.\n", srv_name);

	} while (0);

	ret = ipcon_free_handler(handler);

	return ret;
}
