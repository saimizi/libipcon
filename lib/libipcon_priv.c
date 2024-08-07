#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <netlink/msg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "libipcon_priv.h"
#include "libipcon_dbg.h"

static int ipcon_cb_valid(struct nl_msg *msg, void *arg);
static int ipcon_cb_ack(struct nl_msg *msg, void *arg);

static uint32_t newport(void)
{
	uint32_t rnum = 0;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	srand((unsigned int)tv.tv_usec);
	rnum = (uint32_t)(getpid() & 0xFFFF) << 16 |
	       (rand() % (1 << 16)) & 0xFFFF;

	return rnum;
}

#define NLMSG_MAX_SIZE (8192UL)

static inline int ipcon_chan_init_one(struct ipcon_peer_handler *iph,
				      uint32_t chan_id)
{
	int ret = 0;
	pthread_mutexattr_t mtxAttr;
	struct sockaddr_nl local;
	struct ipcon_channel *ic = NULL;
	struct nl_cb *cb = NULL;

	do {
		if (!iph || chan_id > IPH_CHAN_LAST) {
			ret = -EINVAL;
			break;
		}

		ic = &iph->chan[chan_id];
		ic->iph = iph;
		ret = pthread_mutexattr_init(&mtxAttr);
		if (ret) {
			ret *= -1;
			break;
		}

#ifdef __DEBUG__
		ret = pthread_mutexattr_settype(&mtxAttr,
						PTHREAD_MUTEX_ERRORCHECK);
#else
		ret = pthread_mutexattr_settype(&mtxAttr, PTHREAD_MUTEX_NORMAL);
#endif
		if (ret) {
			ret *= -1;
			break;
		}

		ret = pthread_mutex_init(&ic->mutex, &mtxAttr);
		if (ret) {
			ret *= -1;
			break;
		}

		ic->mutex_initialized = true;

		switch (chan_id) {
		case IPH_C_CHAN:
		case IPH_S_CHAN:
			ic->flags |= IC_FLG_AUTO_ACK;
			break;
		case IPH_R_CHAN:
			ic->flags |= IC_FLG_PEEK;
			break;
		default:
			break;
		}

		cb = nl_cb_alloc(NL_CB_CUSTOM);
		if (!cb) {
			ret = -ENOMEM;
			break;
		}

		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, ipcon_cb_valid,
			  &ic->ir);

		if (ic->flags & IC_FLG_AUTO_ACK)
			nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ipcon_cb_ack,
				  &ic->ir);

		ic->sk = nl_socket_alloc_cb(cb);
		if (!ic->sk) {
			ret = -ENOMEM;
			break;
		}

		if (ic->flags & IC_FLG_AUTO_ACK)
			nl_socket_enable_auto_ack(ic->sk);
		else
			nl_socket_disable_auto_ack(ic->sk);

		if (ic->flags & IC_FLG_PEEK)
			nl_socket_enable_msg_peek(ic->sk);
		else
			nl_socket_disable_msg_peek(ic->sk);

		ret = nl_connect(ic->sk, NETLINK_IPCON);
		if (ret < 0) {
			ret = nlerr2syserr(ret);
			break;
		}

		ic->port = nl_socket_get_local_port(ic->sk);

	} while (0);

	nl_cb_put(cb);

	if (ret < 0)
		ipcon_chan_destory(ic);

	return ret;
}

void *ipconmsg_put(struct nl_msg *msg, struct ipcon_channel *ic,
		   enum ipcon_msg_type type, int flags)
{
	return nlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, type, IPCONMSG_HDRLEN,
			 flags | NLM_F_REQUEST);
};

int ipcon_parse(struct nl_msg *msg, struct nlattr *tb[], int maxtype,
		struct nla_policy *policy)
{
	return nlmsg_parse(nlmsg_hdr(msg), IPCONMSG_HDRLEN, tb, maxtype,
			   policy);
}

struct nlattr *ipcon_find_attr(struct nl_msg *msg, int attrtype)
{
	return nlmsg_find_attr(nlmsg_hdr(msg), IPCONMSG_HDRLEN, attrtype);
}

int ipcon_sendto(struct ipcon_channel *ic, struct nl_msg *msg)
{
	int ret = 0;
	struct sockaddr_nl dst;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	dst.nl_pid = 0;
	dst.nl_groups = 0;
	nlmsg_set_dst(msg, &dst);

	ret = nl_send_auto(ic->sk, msg);
	if (ret < 0)
		ret = nlerr2syserr(ret);
	else
		ret = 0;

	return ret;
}

static int ipcon_cb_valid(struct nl_msg *msg, void *arg)
{
	struct ipconmsg_result *ir = arg;

	assert(!ir->msg);
	nlmsg_get(msg);
	ir->msg = msg;

	//nl_msg_dump(ir->msg, stderr);

	return NL_OK;
}

static int ipcon_cb_ack(struct nl_msg *msg, void *arg)
{
	struct ipconmsg_result *ir = arg;

	assert(ir);
	ir->flags |= IR_FLG_ACK_OK;

	return NL_STOP;
}

int ipcon_recvmsg(struct ipcon_channel *ic, struct nl_msg **msg)
{
	int ret = 0;

	ipcon_dbg("Enter %s\n", __func__);
	ret = nl_recvmsgs_default(ic->sk);

	if (msg)
		*msg = ic->ir.msg;
	else
		nlmsg_free(ic->ir.msg);

	memset(&ic->ir, 0, sizeof(ic->ir));

	ipcon_dbg("Leave %s ret = %d\n", __func__, ret);
	return ret < 0 ? nlerr2syserr(ret) : ret;
}

int ipcon_send_rcv(struct ipcon_channel *ic, struct nl_msg *msg,
		   struct nl_msg **rmsg)
{
	int ret = 0;

	ipcon_dbg("Enter %s flag: %lx\n", __func__, ic->ir.flags);

	ret = ipcon_sendto(ic, msg);
	if (ret < 0)
		return nlerr2syserr(ret);

redo:
	ret = nl_recvmsgs_default(ic->sk);
	if (ret < 0)
		return nlerr2syserr(ret);

	if (ic->flags & IC_FLG_AUTO_ACK) {
		ipcon_dbg("Need ACK\n");

		if ((ic->ir.flags & IR_FLG_ACK_OK) == 0) {
			ipcon_dbg("wait ACK\n");
			goto redo;
		} else {
			ipcon_dbg("got ACK\n");
		}
	}

	if (rmsg)
		*rmsg = ic->ir.msg;
	else
		nlmsg_free(ic->ir.msg);

	memset(&ic->ir, 0, sizeof(ic->ir));

	ipcon_dbg("Leave %s ret = %d\n", __func__, ret);
	return ret;
}

int ipcon_chan_init(struct ipcon_peer_handler *iph)
{
	int ret = 0;

	do {
		struct nl_msg *msg = NULL;
		void *p = NULL;
		uint32_t ipcon_flag = 0;

		if (!iph || !iph->name) {
			ret = -EINVAL;
			break;
		}

		ret = ipcon_chan_init_one(iph, IPH_C_CHAN);
		if (ret < 0)
			break;

		ipcon_dbg("Name: %s.\n", iph->name);
		ipcon_dbg("Flags: %lx.\n", iph->flags);
		ipcon_dbg("Ctrl port: %lu.\n", (unsigned long)iph->c_chan.port);

		if (iph->flags & IPH_FLG_RCV_IF) {
			ipcon_dbg("IPH_FLG_RCV_IF is ON.\n");
			ipcon_flag |= IPCON_FLG_RCV_IF;
			ret = ipcon_chan_init_one(iph, IPH_R_CHAN);
			if (ret < 0)
				break;

			ipcon_dbg("Receive port: %lu.\n",
				  (unsigned long)iph->r_chan.port);
		} else {
			ipcon_dbg("IPH_FLG_RCV_IF is OFF.\n");
		}

		if (iph->flags & IPH_FLG_SND_IF) {
			ipcon_dbg("IPH_FLG_SND_IF is ON.\n");
			ipcon_flag |= IPCON_FLG_SND_IF;
			ret = ipcon_chan_init_one(iph, IPH_S_CHAN);
			if (ret < 0)
				break;
			ipcon_dbg("Send port: %lu.\n",
				  (unsigned long)iph->s_chan.port);
		} else {
			ipcon_dbg("IPH_FLG_SND_IF is OFF.\n");
		}

		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		/* Register the peer */
		ipconmsg_put(msg, &iph->c_chan, IPCON_PEER_REG, 0);

		nla_put_string(msg, IPCON_ATTR_PEER_NAME, iph->name);
		nla_put_u32(msg, IPCON_ATTR_SPORT, iph->s_chan.port);
		nla_put_u32(msg, IPCON_ATTR_RPORT, iph->r_chan.port);
		if (iph->flags & IPH_FLG_ANON_PEER) {
			ipcon_dbg("IPH_FLG_ANON_PEER is ON.\n");
			ipcon_flag |= IPCON_FLG_ANON_PEER;
		}

		if (iph->flags & IPH_FLG_DISABLE_KEVENT_FILTER) {
			ipcon_dbg("IPH_FLG_DISABLE_KEVENT_FILTER is ON.\n");
			ipcon_flag |= IPCON_FLG_DISABL_KEVENT_FILTER;
		}

		nla_put_u32(msg, IPCON_ATTR_FLAG, ipcon_flag);

		ipconmsg_complete(&iph->c_chan, msg);

		ret = ipcon_send_rcv(&iph->c_chan, msg, NULL);

	} while (0);

	if (ret < 0) {
		ipcon_chan_destory(&iph->c_chan);
		ipcon_chan_destory(&iph->s_chan);
		ipcon_chan_destory(&iph->r_chan);
	}

	return ret;
}

void ipcon_chan_destory(struct ipcon_channel *ic)
{
	if (!ic)
		return;

	if (ic->sk) {
		nl_close(ic->sk);
		ic->sk = 0;
	}

	if (ic->mutex_initialized) {
		pthread_mutex_destroy(&ic->mutex);
		ic->mutex_initialized = false;
	}
};
