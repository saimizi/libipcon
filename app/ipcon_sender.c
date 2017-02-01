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
	fprintf(stderr, "[ipcon_sender] Debug: "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[ipcon_sender] Info: "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[ipcon_sender] Error: "fmt, ##__VA_ARGS__)

#define srv_name	"ipcon_server"
__u32 srv_port;
int should_send_msg;

static void ipcon_kevent(struct ipcon_kevent *ik)
{
	if (!ik)
		return;

	switch (ik->type) {
	case IPCON_EVENT_SRV_ADD:
		if (!strcmp(ik->srv.name, srv_name) && !srv_port) {
			srv_port = ik->srv.portid;
			should_send_msg = 1;
			ipcon_info("Service %s detected at %lu.\n",
				srv_name, (unsigned long)srv_port);
		}
		break;
	case IPCON_EVENT_SRV_REMOVE:
		if (!strcmp(ik->srv.name, srv_name) && srv_port) {
			srv_port = 0;
			should_send_msg = 0;
			ipcon_info("Service %s is detected to be removed.\n",
				srv_name);
		}
		break;
	default:
		break;
	}
}

int main(int argc, char *argv[])
{

	int ret = 0;
	IPCON_HANDLER	handler;
	int ipcon_kevent_group = 0;
	int should_quit = 0;

	if (!argv[1]) {
		ipcon_err("No message specified.\n");
		return 1;
	}

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

		ret = ipcon_find_service(handler, srv_name, &srv_port);
		if (ret < 0) {
			if (ret == -ENOENT)
				ipcon_info("Service %s not found.\n", srv_name);
			else
				ipcon_err("Failed to find service: %s (%d)\n",
					strerror(-ret), -ret);
		} else {
			should_send_msg = 1;
		}

		while (!should_quit) {
			int len = 0;
			void *buf = NULL;
			__u32 port;
			__u32 group;
			__u32 type = 0;

			if (should_send_msg) {
				ipcon_info("Send %s to server %lu\n", argv[1],
					(unsigned long)srv_port);
				ret = ipcon_send_unicast(handler,
						srv_port,
						argv[1],
						strlen(argv[1]) + 1);
				if (ret < 0)
					ipcon_err("Send msg error: %s(%d)\n.",
						strerror(-ret), -ret);
			}

			len = ipcon_rcv(handler, &port, &group, &type,
					&buf);
			if (len < 0) {
				ipcon_err("Rcv mesg failed: %s(%d).\n",
					strerror(-len), -len);
				continue;
			}

			if (type == IPCON_NORMAL_MSG) {
				if (port == srv_port) {
					ipcon_info("Server return: %s\n",
						(char *)buf);
					should_send_msg = 1;
				}

				if (!strcmp(buf, "bye"))
					should_quit = 1;

			} else if (type == IPCON_GROUP_MSG) {
				if (group == ipcon_kevent_group)
					ipcon_kevent(buf);

				free(buf);
			}

			sleep(1);
		}

	} while (0);

	ret = ipcon_free_handler(handler);

	return ret;
}
