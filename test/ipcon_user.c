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

IPCON_HANDLER user_h;
#define MYNAME	(user_h ? ipcon_selfname(user_h) : "ANON")

void ipcon_user_grp_cb(char *peer_name, char *group_name,
			void *buf, size_t len, void *data)
{

	struct ts_msg *tm = NULL;
	char logbuf[TSLOG_BUF_SIZE];

	if (!strcmp(buf, "bye")) {
		ipcon_async_rcv_stop(user_h);
		return;
	}

	tm = (struct ts_msg *)buf;
	tsm_recod("USR", tm);
	tsm_delta(tm, logbuf, TSLOG_BUF_SIZE);
	ipcon_logger(user_h, logbuf);

}

static void ipcon_user_grp_join(char *peer_name,
			char *group_name, void *data)
{
	ipcon_info("joined %s.%s\n", peer_name, group_name);
}

static void ipcon_user_grp_leave(char *peer_name,
			char *group_name, void *data)
{
	ipcon_info("left %s.%s\n", peer_name, group_name);
}


#define ARRAY_SIZE(a)	(sizeof(a)/sizeof(a[0]))
int main(int argc, char *argv[])
{
	int ret = 0;
	struct peer_group_info pgi[] = {
			{
				.peer_name	= SRV_NAME,
				.group_name	= GRP_NAME,
				.auto_join	= 1,
			},
	};

	struct async_rcv_ctl arc = {
		.pgi = pgi,
		.num = ARRAY_SIZE(pgi),
		.cb = {
			.group_msg_cb		= ipcon_user_grp_cb,
			.auto_group_join	= ipcon_user_grp_join,
			.auto_group_leave	= ipcon_user_grp_leave,
		}
	};

	do {
		user_h = ipcon_create_handler(NULL, LIBIPCON_FLG_USE_RCV_IF);
		if (!user_h) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		ret = ipcon_async_rcv(user_h, &arc);

		/* Free handler */
		ipcon_free_handler(user_h);


	} while (0);

	exit(ret);

}
