#ifndef __LIBIPCON_PRIV_H__
#define __LIBIPCON_PRIV_H__

#include "libipcon.h"

#define IPCON_ANY_CMD	IPCON_CMD_MAX
#define IPCON_ANY_PORT	0xFFFFFFFF

struct ipcon_grp_info {
	char *name[IPCON_MAX_GRP_NAME_LEN];
	__u32 groupid;
};

struct ipcon_srv_info {
	char *name[IPCON_MAX_SRV_NAME_LEN];
};

struct ipcon_msg_queue {
	struct nl_msg *msg;
	struct ipcon_msg_queue *next;
};

struct ipcon_peer_handler {
	struct nl_sock *sk;
	int ipcon_family;
	__u32 port;
	struct ipcon_grp_info grp[IPCON_MAX_USR_GROUP];
	struct ipcon_srv_info srv;
	struct ipcon_msg_queue *mq;
	pthread_mutex_t mutex;
};

#define handler_to_iph(h) ((struct ipcon_peer_handler *) h)
#define iph_to_handler(i) ((IPCON_HANDLER) i)

#endif
