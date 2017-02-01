#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "ipcon.h"
#include "libipcon.h"

#define ipcon_dbg(fmt, ...) \
	printf("[ipcon_user] %s-%d " fmt, __func__, __LINE__,  ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	printf("[ipcon_user] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	printf("[ipcon_user] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define grp_name	"str_msg"
__u32 srv_port;
int srv_group_connected;

static void ipcon_kevent(IPCON_HANDLER handler, struct ipcon_msg *im)
{
	int ret = 0;
	struct ipcon_kevent *ik;

	if (!im)
		return;

	ik = (struct ipcon_kevent *)im->buf;

	switch (ik->type) {
	case IPCON_EVENT_GRP_ADD:
		if (!srv_group_connected && !strcmp(ik->grp.name, grp_name)) {
			ret = ipcon_join_group(handler, grp_name, 1);
			if (ret < 0) {
				ipcon_err("Failed to join group %s: %s(%d)\n",
					grp_name,
					strerror(-ret),
					-ret);
			} else {
				ipcon_info("Success to join group %s.\n",
					grp_name);
				srv_group_connected = 1;
			}
		}
		break;
	case IPCON_EVENT_GRP_REMOVE:
		if (srv_group_connected && !strcmp(ik->grp.name, grp_name)) {
			ret = ipcon_leave_group(handler, grp_name);
			if (ret < 0) {
				ipcon_err("Failed to leave group %s: %s(%d)\n",
					grp_name,
					strerror(-ret),
					-ret);
			} else {
				ipcon_info("Success to leave group %s.\n",
					grp_name);
			}
			srv_group_connected = 0;

		}
		break;
	default:
		break;
	}
}



int main(int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;
	unsigned int should_quit = 0;

	do {
		/* Create server handler */
		handler = ipcon_create_handler();
		if (!handler) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		ret = ipcon_join_group(handler,
					IPCON_KERNEL_GROUP_NAME, 0);
		if (ret < 0) {
			ipcon_err("Failed to get %s group :%s(%d).\n",
					IPCON_KERNEL_GROUP_NAME,
					strerror(-ret),
					-ret);
			ret = 1;
			break;
		}

		ipcon_info("Joined %s group.\n", IPCON_KERNEL_GROUP_NAME);

		ret = ipcon_join_group(handler, grp_name, 1);
		if (!ret) {
			srv_group_connected = 1;
			ipcon_info("Joined %s group.\n", grp_name);
		}

		while (!should_quit) {
			struct ipcon_msg im;

			ret = ipcon_rcv(handler, &im);
			if (ret < 0) {
				ipcon_err("Receive msg from failed: %s(%d)\n",
						strerror(-ret), -ret);
				continue;
			}


			if (im.type != IPCON_GROUP_MSG)  {
				ipcon_info("Unexpected message.\n");
				continue;
			}

			if (!strcmp(im.group, grp_name)) {
				if (!strcmp(im.buf, "bye")) {
					ipcon_info("Quit...\n");
					should_quit = 1;
				} else {
					ipcon_info("Msg from %s(len=%d):%s\n",
						grp_name, im.len, im.buf);
				}

				continue;
			}

			if (!strcmp(im.group, IPCON_KERNEL_GROUP_NAME))
				ipcon_kevent(handler, &im);

		}

		/* Free handler */
		ipcon_free_handler(handler);


	} while (0);

	exit(ret);

}
