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
#include <assert.h>
#include <sched.h>

#include "libipcon.h"
#include "timestamp_msg.h"
#include "ipcon_logger.h"

#define ipcon_dbg(fmt, ...) \
	fprintf(stderr, "[ipcon_server_poll] Debug: "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[ipcon_server_poll] Info: "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[ipcon_server_poll] Error: "fmt, ##__VA_ARGS__)

#define PEER_NAME	"ipcon_server"
#define GRP_NAME	"str_msg"

#define SYNC_GRP_MSG	1
#define ASYNC_GRP_MSG	0

static int normal_msg_handler(IPCON_HANDLER handler, struct ipcon_msg *im)
{
	int ret = 0;

	if (!handler || !im)
		return -EINVAL;

	if (!strcmp(im->buf, "bye")) {
		ipcon_send_unicast(handler, im->peer, "bye",
				strlen("bye") + 1);

		ipcon_send_multicast(handler, GRP_NAME, "bye",
				strlen("bye") + 1, ASYNC_GRP_MSG);

		return 1;
	}

	ipcon_logger(handler, "Multicast msg from %s.", im->peer);

	ret = ipcon_send_multicast(handler, GRP_NAME, im->buf,
				im->len, ASYNC_GRP_MSG);

	if (ret < 0) {
		ipcon_err("Failed to send mutlcast message:%s(%d).",
			strerror(-ret), -ret);
		ret = ipcon_send_unicast(handler,
				im->peer,
				"NG",
				strlen("NG") + 1);
	} else {
		ret = ipcon_send_unicast(handler,
				im->peer,
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

	handler = ipcon_create_handler(PEER_NAME,
			LIBIPCON_FLG_DEFAULT);
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {
		ret = ipcon_register_group(handler, GRP_NAME);
		if (ret < 0) {
			ipcon_err("Failed to register group: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}

		ipcon_info("Register group %s succeed.\n", GRP_NAME);

		while (!should_quit) {
			struct ipcon_msg im;
			struct timeval timeout;

			timeout.tv_sec = 60;
			timeout.tv_usec = 0;

			ret = ipcon_rcv_timeout(handler, &im, &timeout);
			if (ret < 0) {
				if (ret == -ETIMEDOUT) {
					ipcon_info("%s timeout.\n", PEER_NAME);
					ipcon_send_multicast(handler, GRP_NAME,
							"bye",
							strlen("bye") + 1,
							ASYNC_GRP_MSG);
					should_quit = 1;
				} else {
					ipcon_info("%s : %s (%d).\n", PEER_NAME,
						strerror(-ret), -ret);
				}
				continue;


			}

			if (im.type == LIBIPCON_NORMAL_MSG)  {
				struct ts_msg *tm = NULL;

				assert(strcmp(im.peer, PEER_NAME));

				tm = (struct ts_msg *)im.buf;

				tsm_recod("SRV", tm);
				ret = normal_msg_handler(handler, &im);
				if (ret == 1)
					should_quit = 1;

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
