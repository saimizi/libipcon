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
#include "ipcon_logger.h"
#include "timestamp_msg.h"

#define ipcon_dbg(fmt, ...) \
	fprintf(stderr, "[ipcon_sender] Debug: "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[ipcon_sender] Info: "fmt, ##__VA_ARGS__)
#define ipcon_warn(fmt, ...) \
	fprintf(stderr, "[ipcon_sender] Warn: "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[ipcon_sender] Error: "fmt, ##__VA_ARGS__)

#define SRV_NAME	"ipcon_server"
#define PEER_NAME	"ipcon_sender"
int should_send_msg;

static void ipcon_kevent(struct ipcon_msg *im)
{
	struct ipcon_kevent *ik;

	if (!im)
		return;

	ik = (struct ipcon_kevent *)im->buf;

	switch (ik->type) {
	case IPCON_EVENT_PEER_ADD:
		if (!strcmp(ik->peer.name, SRV_NAME)) {
			should_send_msg = 1;
			ipcon_info("Detected peer %s created.\n", SRV_NAME);
		}
		break;
	case IPCON_EVENT_PEER_REMOVE:
		if (!strcmp(ik->peer.name, SRV_NAME)) {
			should_send_msg = 0;
			ipcon_info("Detected service %s removed.\n", SRV_NAME);
		}
		break;
	case IPCON_EVENT_GRP_ADD:
		ipcon_info("Detected group %s.%s added.\n",
				ik->group.peer_name,
				ik->group.name);
		break;
	case IPCON_EVENT_GRP_REMOVE:
		ipcon_info("Detected group %s.%s removed.\n",
				ik->group.peer_name,
				ik->group.name);
		break;
	default:

		break;
	}
}

static int normal_msg_handler(struct ipcon_msg *im)
{
	if (strcmp(im->peer, SRV_NAME)) {
		ipcon_warn("Ignore msg from %s\n", im->peer);
		return -1;
	}

	if (strcmp(im->buf, "OK"))
		return 1;

	return 0;
}

int main(int argc, char *argv[])
{

	int ret = 0;
	IPCON_HANDLER	handler;
	int should_quit = 0;

	handler = ipcon_create_handler(NULL, ANON);
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {

		ret = ipcon_join_group(handler, IPCON_NAME,
				IPCON_KERNEL_GROUP);
		if (ret < 0)
			ipcon_err("Failed to get %s group :%s(%d).\n",
					IPCON_KERNEL_GROUP,
					strerror(-ret),
					-ret);
		else
			ipcon_info("Joined %s group.\n", IPCON_KERNEL_GROUP);

		if (is_peer_present(handler, SRV_NAME) > 0) {
			ipcon_info("Detected service %s.\n", SRV_NAME);
			should_send_msg = 1;
		}

		while (!should_quit) {
			struct ipcon_msg im;
			int skip_sleep = 0;

			if (should_send_msg) {
				struct ts_msg tm;

redo:
				tsm_init(&tm);
				tsm_recod("SEN", &tm);
				ret = ipcon_send_unicast(handler,
						SRV_NAME,
						&tm,
						sizeof(tm));

				if (ret == -EAGAIN) {
					usleep(100000);
					goto redo;
				}

				if (ret < 0 && ret != -ESRCH) {
					/*
					 * if fail on the reason other than the
					 * exit of server, just exit ...
					 */
					ipcon_err("Send msg error: %s(%d), quit\n.",
						strerror(-ret), -ret);

					should_quit = 1;
					continue;
				}

				should_send_msg = 0;
			}

			do {
				ret = ipcon_rcv(handler, &im);
				if (ret < 0) {
					struct logger_msg lm;

					ipcon_err("Rcv mesg failed: %s(%d).\n",
						strerror(-ret), -ret);


					sprintf(lm.msg,
						"receive msg error: %s(%d),quit\n",
						strerror(-ret), -ret);
					ipcon_send_unicast(handler,
							LOGGER_PEER_NAME,
							&lm, sizeof(lm));

					should_quit = 1;
					skip_sleep = 1;
					break;
				}

				if (im.type == IPCON_NORMAL_MSG) {

					ret = normal_msg_handler(&im);

					/* unexpected message */
					if (ret == -1)
						continue;

					/* server asked quit */
					if (ret == 1) {
						should_quit = 1;
						skip_sleep = 1;
					}

					should_send_msg = 1;
					break;


				} else if (im.type == IPCON_GROUP_MSG) {
					if (!strcmp(im.group,
						IPCON_KERNEL_GROUP))
						ipcon_kevent(&im);

					/*
					 * if server peer detected, should send
					 * msg...
					 */
					if (should_send_msg) {
						skip_sleep = 1;
						break;
					}
				}
			} while (1);

			if (!skip_sleep)
				sleep(1);
		}

	} while (0);

	ipcon_free_handler(handler);

	return ret;
}
