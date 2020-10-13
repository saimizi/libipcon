#ifndef __LIBIPCON_PRIV_H__
#define __LIBIPCON_PRIV_H__

#include "libipcon.h"
#include "util.h"

#define IPCON_ANY_CMD	IPCON_CMD_MAX
#define IPCON_ANY_PORT	0xFFFFFFFF

struct ipcon_channel {
	struct nl_sock *sk;
	__u32 port;
	pthread_mutex_t mutex;
	struct ipcon_peer_handler *iph;
};

struct ipcon_group_info {
	struct link_entry le; /* Must be first */
	char group_name[IPCON_MAX_NAME_LEN];
	char peer_name[IPCON_MAX_NAME_LEN];
	__u32 groupid;
};

#define IPH_FLG_ANON_PEER		(1<<0)
struct ipcon_peer_handler {
	struct link_entry_head grp; /* Must be first */
	char *name;
	uint32_t flags;
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

/*
 * Basically libnl error code are not expected.
 * We just want a errno number which is partly destroyed by libnl...
 * Any internal error in libnl, return -EREMOTEIO.
 */

static inline int nlerr2syserr(int nlerr)
{
	switch (abs(nlerror)) {
	case NLE_BAD_SOCK:	return EBADF;
	case NLE_EXIST:		return EEXIST;
	case NLE_NOADDR:	return EADDRNOTAVAIL;
	case NLE_OBJ_NOTFOUND:	return ENOENT;
	case NLE_INTR:		return EINTR;
	case NLE_AGAIN:		return EAGAIN;
	case NLE_INVAL:		return EINVAL;
	case NLE_NOACCESS:	return EACCES;
	case NLE_NOMEM:		return ENOMEM;
	case NLE_AF_NOSUPPORT:	return EAFNOSUPPORT;
	case NLE_PROTO_MISMATCH:return EPROTONOSUPPORT;
	case NLE_OPNOTSUPP:	return EOPNOTSUPP;
	case NLE_PERM:		return EPERM;
	case NLE_BUSY:		return EBUSY;
	case NLE_RANGE:		return ERANGE;
	case NLE_NODEV:		return ENODEV;
	default:		return EREMOTEIO;
}

#endif
