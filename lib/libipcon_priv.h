#ifndef __LIBIPCON_PRIV_H__
#define __LIBIPCON_PRIV_H__

#include "ipcon.h"
#include "libipcon.h"
#include <linux/netlink.h>
#include <netlink/msg.h>
#include <pthread.h>
#include "util.h"

#define IPCON_ANY_CMD	IPCON_CMD_MAX
#define IPCON_ANY_PORT	0xFFFFFFFF

#define IR_FLG_ACK_OK	(1UL << 0)
struct ipconmsg_result {
	struct nl_msg *msg;
	unsigned long flags;
};

#define IC_FLG_AUTO_ACK		(1UL << 0)
#define IC_FLG_PEEK		(1UL << 1)
struct ipcon_channel {
	struct nl_sock *sk;
	__u32 port;
	pthread_mutex_t mutex;
	struct ipcon_peer_handler *iph;
	struct ipconmsg_result ir;
	unsigned long flags;
};

struct ipcon_group_info {
	struct link_entry le; /* Must be first */
	char group_name[IPCON_MAX_NAME_LEN];
	char peer_name[IPCON_MAX_NAME_LEN];
	__u32 groupid;
};

enum {
	IPH_C_CHAN = 0,
	IPH_S_CHAN = 1,
	IPH_R_CHAN = 2,
	IPH_CHAN_LAST = IPH_R_CHAN
};

#define IPH_FLG_ANON_PEER		(1UL << 0)
#define IPH_FLG_DISABLE_KEVENT_FILTER	(1UL << 1)
#define IPH_FLG_ASYNC_IO		(1UL << 2)
struct ipcon_peer_handler {
	struct link_entry_head grp; /* Must be first */
	char *name;
	unsigned long flags;
#define	c_chan	chan[0]
#define	s_chan	chan[1]
#define	r_chan	chan[2]
	struct ipcon_channel chan[3];
	pthread_t	async_rcv_thread_id;
	struct async_rcv_ctl *arc;
};

static inline void ipcon_c_lock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_lock(&iph->c_chan.mutex);
}

static inline int ipcon_c_trylock(struct ipcon_peer_handler *iph)
{
	return -pthread_mutex_trylock(&iph->c_chan.mutex);
}

static inline void ipcon_c_unlock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_unlock(&iph->c_chan.mutex);
}

static inline void ipcon_s_lock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_lock(&iph->s_chan.mutex);
}

static inline int ipcon_s_trylock(struct ipcon_peer_handler *iph)
{
	return -pthread_mutex_trylock(&iph->s_chan.mutex);
}

static inline void ipcon_s_unlock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_unlock(&iph->s_chan.mutex);
}

static inline void ipcon_r_lock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_lock(&iph->r_chan.mutex);
}

static inline int ipcon_r_trylock(struct ipcon_peer_handler *iph)
{
	return -pthread_mutex_trylock(&iph->r_chan.mutex);
}

static inline void ipcon_r_unlock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_unlock(&iph->r_chan.mutex);
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
	switch (abs(nlerr)) {
	case NLE_BAD_SOCK:	return -EBADF;
	case NLE_EXIST:		return -EEXIST;
	case NLE_NOADDR:	return -EADDRNOTAVAIL;
	case NLE_OBJ_NOTFOUND:	return -ENOENT;
	case NLE_INTR:		return -EINTR;
	case NLE_AGAIN:		return -EAGAIN;
	case NLE_INVAL:		return -EINVAL;
	case NLE_NOACCESS:	return -EACCES;
	case NLE_NOMEM:		return -ENOMEM;
	case NLE_AF_NOSUPPORT:	return -EAFNOSUPPORT;
	case NLE_PROTO_MISMATCH:return -EPROTONOSUPPORT;
	case NLE_OPNOTSUPP:	return -EOPNOTSUPP;
	case NLE_PERM:		return -EPERM;
	case NLE_BUSY:		return -EBUSY;
	case NLE_RANGE:		return -ERANGE;
	case NLE_NODEV:		return -ENODEV;
	default:
		break;
	}
	return -EREMOTEIO;
}

static inline __u16 ipconmsg_type(struct nl_msg *msg)
{
	return (nlmsg_hdr(msg))->nlmsg_type;
}

static inline void ipconmsg_complete(struct ipcon_channel *ic,
		struct nl_msg *msg)
{
	nl_complete_msg(ic->sk, msg);
}

void *ipconmsg_put(struct nl_msg *msg, struct ipcon_channel *ic,
		enum ipcon_msg_type type, int flags);

int ipcon_chan_init(struct ipcon_peer_handler *iph);
void ipcon_chan_destory(struct ipcon_channel *ic);
int ipcon_recvmsg(struct ipcon_channel *ic, struct nl_msg **msg);
int ipcon_send_rcv(struct ipcon_channel *ic, struct nl_msg *msg,
			struct nl_msg **rmsg);
int ipcon_parse(struct nl_msg *msg, struct nlattr *tb[], int maxtype,
		const struct nla_policy *policy);
struct nlattr *ipcon_find_attr(struct nl_msg *msg,  int attrtype);


#endif
