#ifndef __LIBIPCON_PRIV_H__
#define __LIBIPCON_PRIV_H__

#include "libipcon.h"
#include "util.h"

#define IPCON_ANY_CMD	IPCON_CMD_MAX
#define IPCON_ANY_PORT	0xFFFFFFFF

struct ipcon_channel {
	struct nl_sock *sk;
	int family;
	__u32 port;
	pthread_mutex_t mutex;
};

struct ipcon_group_info {
	struct link_entry le; /* Must be first */
	char grpname[IPCON_MAX_NAME_LEN];
	char srvname[IPCON_MAX_NAME_LEN];
	__u32 groupid;
};

struct ipcon_peer_handler {
	struct link_entry_head grp; /* Must be first */
	char *name;
	struct ipcon_channel chan;
	struct ipcon_channel ctrl_chan;
};

static inline void ipcon_ctrl_lock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_lock(&iph->ctrl_chan.mutex);
}

static inline int ipcon_ctrl_trylock(struct ipcon_peer_handler *iph)
{
	return -pthread_mutex_trylock(&iph->ctrl_chan.mutex);
}

static inline void ipcon_ctrl_unlock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_unlock(&iph->ctrl_chan.mutex);
}

static inline void ipcon_com_lock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_lock(&iph->chan.mutex);
}

static inline int ipcon_com_trylock(struct ipcon_peer_handler *iph)
{
	return -pthread_mutex_trylock(&iph->chan.mutex);
}

static inline void ipcon_com_unlock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_unlock(&iph->chan.mutex);
}

#define handler_to_iph(h) ((struct ipcon_peer_handler *) h)
#define iph_to_handler(i) ((IPCON_HANDLER) i)

#endif
