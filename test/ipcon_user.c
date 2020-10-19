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
#include "timestamp_msg.h"
#include "ipcon_logger.h"

#define ipcon_dbg(fmt, ...) \
	printf("[ipcon_user] %s-%d " fmt, __func__, __LINE__,  ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	printf("[ipcon_user] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	printf("[ipcon_user] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define SRV_NAME	"ipcon_server"
#define GRP_NAME	"str_msg"
#define PEER_NAME	"ipcon_user"
__u32 srv_port;
int srv_group_connected;

IPCON_HANDLER kevent_h;
IPCON_HANDLER user_h;
#define MYNAME	(user_h ? ipcon_selfname(user_h) : "ANON")

static void ipcon_kevent(struct ipcon_msg *im)
{
	int ret = 0;
	struct libipcon_kevent *ik;

	if (!im)
		return;

	ik = &im->kevent;

	switch (ik->type) {
	case LIBIPCON_EVENT_GRP_ADD:
		if (srv_group_connected)
			break;

		if (!strcmp(ik->group.name, GRP_NAME) &&
			!strcmp(ik->group.peer_name, SRV_NAME)) {
			ret = ipcon_join_group(user_h, SRV_NAME, GRP_NAME);
			if (ret < 0) {
				ipcon_err("%s: Failed to join %s: %s(%d)\n",
					MYNAME,
					GRP_NAME,
					strerror(-ret),
					-ret);
			} else {
				ipcon_info("%s: Success to join %s.\n",
					MYNAME,
					GRP_NAME);
				srv_group_connected = 1;
			}
		}
		break;

	case LIBIPCON_EVENT_GRP_REMOVE:
		if (!srv_group_connected)
			break;

		if (!strcmp(ik->group.name, GRP_NAME) &&
			!strcmp(ik->group.peer_name, SRV_NAME)) {

			ret = ipcon_leave_group(user_h, SRV_NAME, GRP_NAME);
			if (ret < 0) {
				ipcon_err("%s: Failed to leave %s: %s(%d)\n",
					MYNAME,
					GRP_NAME,
					strerror(-ret),
					-ret);
			} else {
				ipcon_info("%s: Success to leave %s.\n",
					MYNAME,
					GRP_NAME);
			}
			srv_group_connected = 0;

		}
		break;

	case LIBIPCON_EVENT_PEER_REMOVE:
		ipcon_err("%s: peer %s is remove\n",
			MYNAME,
			ik->peer.name);
		break;
	default:
		break;
	}
}



int main(int argc, char *argv[])
{
	int ret = 0;
	unsigned int should_quit = 0;

	do {
		/* Create server handler */
		kevent_h = ipcon_create_handler(NULL, 0);
		if (!kevent_h) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		user_h = ipcon_create_handler(NULL, 0);
		if (!user_h) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		ret = ipcon_join_group(kevent_h, LIBIPCON_KERNEL_NAME,
				LIBIPCON_KERNEL_GROUP_NAME);
		if (ret < 0) {
			ipcon_err("%s: Failed to join %s :%s(%d).\n", MYNAME,
					LIBIPCON_KERNEL_GROUP_NAME,
					strerror(-ret),
					-ret);
			ret = 1;
			break;
		}

		ipcon_info("%s: Joined %s group.\n", MYNAME,
				LIBIPCON_KERNEL_GROUP_NAME);

		/*
		 * is_group_present() takes the following roles:
		 * 1. judge whether SRV_NAME.GRP_NAME is present.
		 * 2. add SRV_NAME.GRP_NAME into kevent_h's filter so that the
		 * add/remove ipcon kevent of SRV_NAME.GRP_NAME will be sent to
		 * kevent_h.
		 */
		ret = is_group_present(kevent_h, SRV_NAME, GRP_NAME);
		if (ret < 0) {
			ipcon_err("is_group_present failed.\n");
			ret = 1;
			break;
		} else if (ret > 0) {
			ret = ipcon_join_group(user_h, SRV_NAME, GRP_NAME);
			if (!ret) {
				srv_group_connected = 1;
				ipcon_info("%s: Joined %s group.\n", MYNAME,
					GRP_NAME);
			}
		}

		while (!should_quit) {
			struct ipcon_msg im;
			fd_set rfds;
			int kfd = ipcon_get_read_fd(kevent_h);
			int ufd = ipcon_get_read_fd(user_h);
			int nfd = (kfd > ufd) ? kfd + 1 : ufd + 1;

			FD_ZERO(&rfds);
			FD_SET(ufd, &rfds);
			FD_SET(kfd, &rfds);

			ret = select(nfd, &rfds, NULL, NULL, NULL);
			if (ret <= 0) {
				ipcon_info("%s: select error :%s\n", MYNAME,
					strerror(errno));
				continue;
			}

			if (FD_ISSET(ufd, &rfds)) {

				ret = ipcon_rcv_nonblock(user_h, &im);
				if (ret < 0) {
					ipcon_err("%s: Rcv %s failed: %s(%d)\n", MYNAME,
						GRP_NAME,
						strerror(-ret),
						-ret);
					abort();
					continue;
				}

				if (im.type != LIBIPCON_GROUP_MSG ||
					strcmp(im.group, GRP_NAME))  {
					ipcon_err("%s: Unexpected msg.\n", MYNAME);
					continue;
				}

				if (!strcmp(im.buf, "bye")) {
					ipcon_info("%s: Quit...\n", MYNAME);
					should_quit = 1;
					continue;
				}

				{
					struct ts_msg *tm = NULL;
					char buf[TSLOG_BUF_SIZE];

					tm = (struct ts_msg *)im.buf;
					tsm_recod("USR", tm);
					tsm_delta(tm, buf, TSLOG_BUF_SIZE);
					ipcon_logger(user_h, buf);
				}


			} else if (FD_ISSET(kfd, &rfds)) {
				ret = ipcon_rcv_nonblock(kevent_h, &im);
				if (ret < 0) {
					ipcon_err("%s: Rcv %s failed: %s(%d)\n", MYNAME,
						GRP_NAME,
						strerror(-ret),
						-ret);
					continue;
				}

				if (im.type != LIBIPCON_KEVENT_MSG) {
					ipcon_err("%s: Unexpected msg.\n", MYNAME);
					continue;
				}

				ipcon_kevent(&im);
			} else {
				ipcon_err("%s: why am I here ?\n", MYNAME);
			}

		}

		ipcon_leave_group(user_h, SRV_NAME, GRP_NAME);
		ipcon_leave_group(kevent_h, LIBIPCON_KERNEL_NAME,
				LIBIPCON_KERNEL_GROUP_NAME);

		/* Free handler */
		ipcon_free_handler(user_h);
		ipcon_free_handler(kevent_h);


	} while (0);

	exit(ret);

}
