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
int srv_group;
__u32 srv_port;

static void ipcon_kevent(IPCON_HANDLER handler, struct ipcon_kevent *ik)
{
	int ret = 0;

	if (!ik)
		return;

	switch (ik->type) {
	case IPCON_EVENT_GRP_ADD:
		if (!srv_group && !strcmp(ik->grp.name, grp_name)) {
			srv_group = ipcon_join_group(handler, grp_name, 0);
			if (srv_group < 0) {
				ipcon_err("Failed to join group %s: %s(%d)\n",
					grp_name,
					strerror(-srv_group),
					-srv_group);
				srv_group = 0;
			} else {
				ipcon_info("Success to join group %s (%d).\n",
					grp_name,
					srv_group);
			}
		}
		break;
	case IPCON_EVENT_GRP_REMOVE:
		if (srv_group && (srv_group == ik->grp.groupid)) {
			ret = ipcon_leave_group(handler, srv_group);
			if (ret < 0) {
				ipcon_err("Failed to leave group %s: %s(%d)\n",
					grp_name,
					strerror(-ret),
					-ret);
			} else {
				ipcon_info("Success to leave group %s (%d).\n",
					grp_name,
					srv_group);
			}
			srv_group = 0;

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
	int ipcon_kevent_group = 0;

	do {
		/* Create server handler */
		handler = ipcon_create_handler();
		if (!handler) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		ipcon_kevent_group = ipcon_join_group(handler,
					IPCON_KERNEL_GROUP_NAME, 0);
		if (ipcon_kevent_group < 0) {
			ipcon_err("Failed to get %s group :%s(%d).\n",
					IPCON_KERNEL_GROUP_NAME,
					strerror(-ipcon_kevent_group),
					-ipcon_kevent_group);
			ret = 1;
			break;
		}

		ipcon_info("Joined %s group (groupid = %d).\n",
				IPCON_KERNEL_GROUP_NAME,
				ipcon_kevent_group);

		srv_group = ipcon_join_group(handler, grp_name, 0);
		if (srv_group < 0)
			srv_group = 0;
		else
			ipcon_info("Joined %s group (groupid = %d).\n",
					grp_name,
					srv_group);

		/* Wait client */
		while (!should_quit) {
			int len = 0;
			void *buf = NULL;
			__u32 port;
			__u32 group;
			__u32 type = 0;

			len = ipcon_rcv(handler, &port, &group, &type, &buf);
			if (len < 0) {
				ipcon_err("Receive msg from failed: %s(%d)\n",
						strerror(-len), -len);
				break;
			}

			if (type == IPCON_GROUP_MSG)  {
				if (srv_group && (group == srv_group)) {
					if (!strcmp(buf, "bye")) {
						ipcon_info("Quit...\n");
						should_quit = 1;
					} else {
						ipcon_info("MC msg from %s@%u (len=%d) :%s\n",
							grp_name,
							srv_group,
							len,
							(char *)buf);
					}

					free(buf);
					continue;
				}

				if (group == ipcon_kevent_group)
					ipcon_kevent(handler, buf);
			} else {
				ipcon_info("Unexpected message.\n");
			}

			free(buf);
		}

		/* Free handler */
		ipcon_free_handler(handler);


	} while (0);

	exit(ret);

}
