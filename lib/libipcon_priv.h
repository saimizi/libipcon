#ifndef __LIBIPCON_PRIV_H__
#define __LIBIPCON_PRIV_H__

#include "libipcon.h"

#define IPCON_ANY_CMD	IPCON_CMD_MAX
#define IPCON_ANY_PORT	0xFFFFFFFF

struct ipcon_grp_info {
	char *name;
	__u32 groupid;
};

struct ipcon_srv_info {
	char *name;
};

struct ipcon_msg_queue {
	struct nl_msg *msg;
	struct ipcon_msg_queue *next;
};

struct ipcon_channel {
	struct nl_sock *sk;
	struct ipcon_msg_queue *mq;
	int family;
	__u32 port;
	pthread_mutex_t mutex;
};

struct ipcon_peer_handler {
	struct ipcon_channel chan;
	struct ipcon_channel ctrl_chan;
	struct ipcon_grp_info grp[IPCON_MAX_USR_GROUP];
	struct ipcon_srv_info srv;
};

static inline void ipcon_ctrl_lock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_lock(&iph->ctrl_chan.mutex);
}

static inline void ipcon_ctrl_unlock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_unlock(&iph->ctrl_chan.mutex);
}

static inline void ipcon_com_lock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_lock(&iph->chan.mutex);
}

static inline void ipcon_com_unlock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_unlock(&iph->chan.mutex);
}

#define handler_to_iph(h) ((struct ipcon_peer_handler *) h)
#define iph_to_handler(i) ((IPCON_HANDLER) i)

#endif
