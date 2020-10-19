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


static inline int ipcon_sender_send_msg(IPCON_HANDLER handler)
{
	int ret;
	struct ts_msg tm;

redo:
	tsm_init(&tm);
	tsm_recod("SEN", &tm);
	ret = ipcon_send_unicast(handler, SRV_NAME, &tm, sizeof(tm));
	if (ret == -EAGAIN) {
		usleep(100000);
		goto redo;
	}

	return ret;

}

static void  ipcon_sender_peer_add(char *peer_name, void *data)
{
	int ret;

	IPCON_HANDLER	handler = data;

	ipcon_info("Detected service %s.\n", SRV_NAME);
	if (!strcmp(peer_name, SRV_NAME)) {
		ret = ipcon_sender_send_msg(handler);
		if (ret < 0) {
			ipcon_info("Failed to send msg to %s: %s(%d).\n",
					SRV_NAME, strerror(-ret), -ret);
			ipcon_async_rcv_stop(handler);
		}
	}
}

static void  ipcon_sender_peer_remove(char *peer_name, void *data)
{
	ipcon_info("Detected service %s removed.\n", SRV_NAME);
}

static void ipcon_sender_normal_msg(char *peer_name, void *buf,
			size_t len, void *data)
{
	IPCON_HANDLER	handler = data;
	int ret;

	if (strcmp(peer_name, SRV_NAME))
		return;

	if (strcmp(buf, "OK")) {
		ipcon_async_rcv_stop(handler);
		return;
	}

	sleep(1);

	ret = ipcon_sender_send_msg(handler);
	if ((ret < 0) && (ret != -ENOENT))
		ipcon_async_rcv_stop(handler);
}

int main(int argc, char *argv[])
{

	int ret = 0;
	IPCON_HANDLER	handler;
	struct async_rcv_ctl arc = {
		.agi = NULL,
		.num = 0,
		.cb = {
			.peer_add	= ipcon_sender_peer_add,
			.peer_remove	= ipcon_sender_peer_remove,
			.normal_msg_cb	= ipcon_sender_normal_msg,
		}
	};

	handler = ipcon_create_handler(NULL, 0);
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {

		ret = ipcon_join_group(handler, LIBIPCON_KERNEL_NAME,
				LIBIPCON_KERNEL_GROUP_NAME);
		if (ret < 0)
			ipcon_err("Failed to get %s group :%s(%d).\n",
					LIBIPCON_KERNEL_GROUP_NAME,
					strerror(-ret),
					-ret);
		else
			ipcon_info("Joined %s group.\n",
					LIBIPCON_KERNEL_GROUP_NAME);

		if (is_peer_present(handler, SRV_NAME) > 0) {
			ipcon_info("Detected service %s.\n", SRV_NAME);
			ret = ipcon_sender_send_msg(handler);
		}

		arc.cb.data = handler;
		ret = ipcon_async_rcv(handler, &arc);

	} while (0);

	ipcon_free_handler(handler);

	return ret;
}
