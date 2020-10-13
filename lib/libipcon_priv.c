#include <stdint.h>
#include <pthread.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/time.h>
#include "libipcon_priv.h"


static uint32_t newport()
{
	uint32_t rnum = 0;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	srand((unsigned int)tv.tv_usec);
	rnum = (getpid() & 0xFFFF) << 16 | (rand() % (1<<16)) & 0xFFFF;

	return rnum;
}





#define NLMSG_MAX_SIZE	(8192UL)

static inline int ipcon_chan_init_one(struct ipcon_peer_handler *iph, struct ipcon_channel *ic)
{
	int ret = 0;
	pthread_mutexattr_t mtxAttr;
	struct sockaddr_nl local;
	int pthread_mutex_initialized = 0;

	do {

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
		ret = pthread_mutexattr_settype(&mtxAttr,
				PTHREAD_MUTEX_NORMAL);
#endif
		if (ret) {
			ret *= -1;
			break;
		}

		ret = pthread_mutex_init(&ic->mutex, &mtxAttr);
		if (ret) {
			ret *= -1;
		}

		pthread_mutex_initialized = 1;


		ic->sk = nl_socket_alloc();
		if (!ic->sk) {
			ret = -ENOMEM;
			break;
		}

		/* Enable NLM_F_ACK by default */
		nl_socket_enable_auto_ack(ic->sk);

		ret = nl_connect(ic->sk, NETLINK_IPCON);
		if (ret < 0) {
			ret = -nlerr2syserr(ret);
			break;
		}

		ic->port = nl_socket_get_local_port(ic->sk);

	} while (0);

	if (ret < 0) {
		if (ic->sk)
			nl_close(ic->sk);

		if (pthread_mutex_initialized)
			pthread_mutex_destroy(&ic->mutex);
	}


	return ret;
}

void *ipconmsg_put(struct nl_msg *msg, struct ipcon_channel *ic,
		enum ipcon_msg_type type, int flags, __u8 cmd)
{
	struct nlmsghdr *nlh;
	struct ipcon_msghdr *hdr;

	if (!flags)
		flags |= NLM_F_REQUEST;

	nlh = nlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, type,
			IPCONMSG_HDRLEN, flags);
	if (nlh) {
		hdr =  nlmsg_data(nlh);
		hdr->cmd = cmd;
		hdr->version = 1;
	}

	return hdr;
};

int ipcon_parse(struct nl_msg *msg, struct nlattr *tb[], int maxtype,
		const struct nla_policy *policy)
{
	return nlmsg_parse(nlmsg_hdr(msg), IPCONMSG_HDRLEN, tb, maxtype, policy);
}

struct nlattr *ipcon_find_attr(struct nl_msg *msg,  int attrtype)
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
		ret = -nlerr2syserr(ret);
	else
		ret = 0;

	return ret;
}

struct ipconmsg_result {
	int ret;
	struct nl_msg *msg;
}

int ipcon_cb_valid(struct nl_msg *msg, void *arg)
{
	struct ipconmsg_result *ir = arg;

	nlmsg_get(msg);
	ir->msg = msg;
}

int ipcon_recvmsg(struct ipcon_channel *ic, struct nl_msg **msg)
{
	int ret = 0;
	struct ipconmsg_result ir = {
		.ret = 0,
		.msg = NULL;
	};
	struct nl_cb *cb = nl_cb_alloc(NL_CB_CUSTOM);

	assert(cb);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, ipcon_cb_valid, &ir);
	ret = nl_recvmsgs(ic->sk, cb);

	if (msg)
		*msg = ir->msg;
	else 
		nlmsg_free(ir->msg);

	return ret;
}

int ipcon_send_rcv(struct ipcon_channel *ic, struct nl_msg *msg,
			struct nl_msg **rmsg)
{
	int ret = 0;

	do {
		ret = ipcon_sendto(ic, msg);
		if (!ret) 
			ret = ipcon_recvmsg(ic, rmsg);
	} while (0);

	return ret;
}

int ipcon_chan_init(struct ipcon_peer_handler *iph)
{
	int ret = 0;

	do {
		struct nl_msg *msg = NULL;
		void *p = NULL;

		if (!ic || !iph || !iph->name) {
			ret = -EINVAL;
			break;
		}	

		ret = ipcon_chan_init_one(iph, iph->ctrl_chan);
		if (ret < 0)
			break;

		ret = ipcon_chan_init_one(iph, iph->chan);
		if (ret < 0)
			break;

		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}
		
		/* Register the peer */
		ipconmsg_put(msg, &iph->ctrl_chan, IPCON_TYPE_CTL,
				0, IPCON_PEER_REG);

		nla_put_string(msg, IPCON_ATTR_PEER_NAME, iph->name);
		nla_put_u32(msg, IPCON_ATTR_PORT, iph->chan.port);
		if (iph->flags | IPH_FLG_ANON_PEER)
			nla_put_u32(msg, IPCON_ATTR_FLAG, IPCON_FLG_ANON_PEER);

		nl_complete_msg(&iph->ctrl_chan, msg);

		ret = ipcon_send_rcv(&iph->ctrl_chan, msg, NULL);
		nlmsg_free(msg);

	} while (0);

	if (ret < 0) {
		if (iph->ctrl_chan.sk)
			ipcon_chan_destory(&iph->ctrl_chan);
		if (iph->chan.sk)
			ipcon_chan_destory(&iph->chan);
	}

}


static inline void ipcon_chan_destory(struct ipcon_channel *ic)
{
	if (!ic)
		return;

	nl_close(ic->sk);
	pthread_mutex_destroy(&ic->mutex);
};
