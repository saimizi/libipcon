#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <netlink/netlink.h>
#include <netlink/errno.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <pthread.h>

#include "libipcon_dbg.h"
#include "libipcon_priv.h"

/*
 * Basically libnl error code are not expected.
 * We just want a errno number which is partly destroyed by libnl...
 * Any internal error in libnl, return -EREMOTEIO.
 */
static inline int libnl_error(int error)
{
	error = abs(error);

	switch (error) {
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
	default:		return -EREMOTEIO;
	}
}

struct ipcon_rcv_msg_info {
	struct ipcon_channel *ic;
	__u32 target_port;
	int target_cmd;
	struct nl_msg *msg;
};


static struct nla_policy ipcon_policy[NUM_IPCON_ATTR] = {
	[IPCON_ATTR_MSG_TYPE] = {.type = NLA_U32},
	[IPCON_ATTR_PORT] = {.type = NLA_U32},
	[IPCON_ATTR_SRV_NAME] = {.type = NLA_NUL_STRING,
				.maxlen = IPCON_MAX_SRV_NAME_LEN - 1 },
	[IPCON_ATTR_GROUP] = {.type = NLA_U32},
	[IPCON_ATTR_GRP_NAME] = {.type = NLA_NUL_STRING,
				.maxlen = IPCON_MAX_GRP_NAME_LEN - 1 },
	[IPCON_ATTR_DATA] = {.type = NLA_BINARY, .maxlen = IPCON_MAX_MSG_LEN},
};

static inline void *ipcon_put(struct nl_msg *msg, struct ipcon_channel *ic,
		int flags, uint8_t cmd)
{
	return genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ic->family,
			IPCON_HDR_SIZE, flags, cmd, 1);
};

static int queue_msg(struct ipcon_msg_queue **head, struct nl_msg *msg)
{
	int ret = 0;

	if (!head || !msg)
		return -EINVAL;

	do {

		if (*head) {
			struct ipcon_msg_queue *t = *head;

			while (t->next)
				t = t->next;

			t->next = malloc(sizeof(struct ipcon_msg_queue));
			if (t->next) {
				ret = -ENOMEM;
				break;
			}

			t->next->msg = msg;
		} else {
			*head = malloc(sizeof(struct ipcon_msg_queue));
			if (!(*head)) {
				ret = -ENOMEM;
				break;
			}

			(*head)->msg = msg;
		}
	} while (0);

	return ret;
}

static struct nl_msg *dequeue_msg(struct ipcon_msg_queue **head)
{
	struct nl_msg *msg = NULL;
	struct ipcon_msg_queue *imq = NULL;

	if (!head || !(*head))
		return NULL;

	imq = (*head);
	msg = (*head)->msg;
	*head = imq->next;
	free(imq);

	return msg;
}


static inline int port_match(__u32 port1, __u32 port2)
{
	if ((port1 == IPCON_ANY_PORT) || (port2 == IPCON_ANY_PORT))
		return 1;

	return (port1 == port2);
}

static inline int cmd_match(int cmd1, int cmd2)
{
	if ((cmd1 == IPCON_ANY_CMD) || (cmd2 == IPCON_ANY_CMD))
		return 1;

	return (cmd1 == cmd2);
}

static inline int rcvmsg_match_cond(struct nl_msg *msg,
				__u32 src_port, int target_cmd)
{
	struct nlmsghdr *nlh = NULL;
	struct genlmsghdr *genlh = NULL;
	struct sockaddr_nl *src_addr;

	if (!msg)
		return 0;

	nlh = nlmsg_hdr(msg);
	genlh = nlmsg_data(nlh);
	src_addr = nlmsg_get_src(msg);

	if (port_match(src_addr->nl_pid, src_port) &&
		cmd_match(genlh->cmd, target_cmd))
		return 1;

	return 0;
}

static struct nl_msg *dequeue_msg_cond(struct ipcon_msg_queue **head,
				__u32 target_port, int target_cmd)
{
	struct nl_msg *msg = NULL;
	struct ipcon_msg_queue *srh = NULL;
	struct ipcon_msg_queue *psrh = NULL;

	if (!head || !(*head))
		return NULL;

	psrh = srh = *head;

	while (srh) {
		struct nlmsghdr *nlh = nlh = nlmsg_hdr(srh->msg);
		struct genlmsghdr *genlh = genlh = nlmsg_data(nlh);
		__u32 src_port = nlmsg_get_src(srh->msg)->nl_pid;
		int cmd = genlh->cmd;

		if (port_match(src_port, target_port) &&
			cmd_match(cmd, target_cmd)) {

			if (srh == *head)
				*head = srh->next;
			else
				psrh->next = srh->next;

			srh->next = NULL;
			break;
		}

		psrh = srh;
		srh = srh->next;
	}

	if (srh) {
		msg = srh->msg;
		free(srh);
	}

	return msg;
}

/*
 * CB for valid messages
 *
 */
static int valid_msg_cb(struct nl_msg *msg, void *arg)
{
	struct ipcon_rcv_msg_info *irmi = arg;
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *genlh = nlmsg_data(nlh);
	struct sockaddr_nl *src_addr;

	if (!irmi || !irmi->ic) {
		ipcon_err("valid msg losted for null handler.\n");
		return -EINVAL;
	}

	if (nlh->nlmsg_type != irmi->ic->family)
		return NL_SKIP;

	nlmsg_get(msg);

	if (rcvmsg_match_cond(msg, irmi->target_port, irmi->target_cmd))
		irmi->msg = msg;
	else
		queue_msg(&irmi->ic->mq, msg);

	return NL_OK;
}

/*
 * ipcon_rcv_msg
 *
 * Receive a specified message.
 * Message may be disordered, so this function is just an internal one.
 *
 * If a not matched message is recevied, it will be queued and -EAGAIN is
 * returned. while, nlerror message will never be queued. Since nlerror message
 * is processed sychronously by exclusion, there is no case that a nlerror
 * message will be miss received. error code of the nlerror will be returned.
 *
 * target_port: receive from a specified port, a IPCON_ANY_PORT match any port.
 * target_cmd:  receive a specified cmd, a IPCON_ANY_CMD match any command.
 */

static int ipcon_rcv_msg(struct ipcon_channel *ic,
			__u32 target_port, int target_cmd, struct nl_msg **pmsg)
{

	struct ipcon_rcv_msg_info irmi;
	struct nl_msg *msg = NULL;
	int ret = 0;

	if (!ic)
		return -EINVAL;

	msg = dequeue_msg_cond(&ic->mq, target_port, target_cmd);
	if (msg) {
		if (pmsg)
			*pmsg = msg;
		return 0;
	}

	irmi.ic = ic;
	irmi.target_port = target_port;
	irmi.target_cmd = target_cmd;
	irmi.msg = NULL;

	nl_socket_modify_cb(ic->sk,
			NL_CB_VALID,
			NL_CB_CUSTOM,
			valid_msg_cb,
			(void *)&irmi);

	ret = nl_recvmsgs_default(ic->sk);
	if (!ret) {
		/*
		 * If target message is not received, just return -EAGAIN to
		 * inform caller. Do NOT loop here to wait the target message so
		 * that non-block I/O can also be processed.
		 *
		 * if caller doesn't specify pmsg, error information is just
		 * wanted. nlmsg_free() can deal with NULL pointer, no check
		 * need.
		 */
		if (pmsg && !irmi.msg)
			ret = -EAGAIN;
		else if (pmsg)
			*pmsg = irmi.msg;
		else
			nlmsg_free(irmi.msg);
	} else {
		ret = libnl_error(ret);
	}

	return ret;
}

static int ipcon_send_msg(struct ipcon_channel *ic, __u32 port,
			struct nl_msg *msg, int need_ack)
{
	int ret = 0;
	uint32_t  old_peer_port;

	if (!ic || !ic->sk || !msg)
		return -EINVAL;

	if (need_ack)
		nl_socket_enable_auto_ack(ic->sk);

	old_peer_port = nl_socket_get_peer_port(ic->sk);
	nl_socket_set_peer_port(ic->sk, port);
	ret = nl_send_auto(ic->sk, msg);
	nl_socket_set_peer_port(ic->sk, old_peer_port);

	if (ret >= 0)
		ret = 0;
	else
		ret = libnl_error(ret);

	nl_socket_disable_auto_ack(ic->sk);

	return ret;
}


static inline int ipcon_chan_init(struct ipcon_channel *ic)
{
	int ret = 0;
	pthread_mutexattr_t mtxAttr;

	if (!ic)
		return -EINVAL;

	ret = pthread_mutexattr_init(&mtxAttr);
	if (ret)
		return ret;

#ifdef __DEBUG__
	ret = pthread_mutexattr_settype(&mtxAttr, PTHREAD_MUTEX_ERRORCHECK);
#else
	ret = pthread_mutexattr_settype(&mtxAttr, PTHREAD_MUTEX_NORMAL);
#endif
	if (ret)
		return ret;

	ret = pthread_mutex_init(&ic->mutex, &mtxAttr);
	if (ret)
		return ret;

	ic->mq = NULL;
	ic->family = 0;

	ic->sk = nl_socket_alloc();
	if (!ic->sk) {
		pthread_mutex_destroy(&ic->mutex);
		return -ENOMEM;
	}

	ret = genl_connect(ic->sk);
	if (ret < 0) {
		pthread_mutex_destroy(&ic->mutex);
		nl_socket_free(ic->sk);
	}

	ic->port = nl_socket_get_local_port(ic->sk);

	return ret;
}

static inline void ipcon_chan_destory(struct ipcon_channel *ic)
{
	if (!ic)
		return;

	nl_socket_free(ic->sk);
	if (ic->mq) {
		struct nl_msg *msg = NULL;

		do {
			msg = dequeue_msg(&ic->mq);
			nlmsg_free(msg);
		} while (msg);

		ic->mq = NULL;
	}
	ic->family = 0;
	pthread_mutex_destroy(&ic->mutex);
};

/*
 * ipcon_create_handler
 * Create and return a ipcon handler with an internal structure ipcon_mng_info.
 */

IPCON_HANDLER ipcon_create_handler(void)
{
	struct ipcon_peer_handler *iph = NULL;
	int gi = 0;
	int ret = 0;

	iph = malloc(sizeof(*iph));
	if (!iph)
		return NULL;

	do {
		int i;
		int family;

		if (ipcon_chan_init(&iph->chan))
			break;
		ipcon_dbg("Communictaion channel port: %lu.\n",
				(unsigned long)iph->chan.port);

		if (ipcon_chan_init(&iph->ctrl_chan))
			break;
		ipcon_dbg("Ctrl channel port: %lu.\n",
				(unsigned long)iph->ctrl_chan.port);

		family = genl_ctrl_resolve(iph->ctrl_chan.sk, IPCON_GENL_NAME);
		if (family < 0)
			break;

		iph->ctrl_chan.family = iph->chan.family = family;

		/* We don't required a ACK by default */
		nl_socket_disable_auto_ack(iph->chan.sk);
		nl_socket_disable_auto_ack(iph->ctrl_chan.sk);

		return iph_to_handler(iph);

	} while (0);

	/* NULL is ok for ipcon_chan_destory() */
	ipcon_chan_destory(&iph->chan);
	ipcon_chan_destory(&iph->ctrl_chan);
	free(iph);

	return NULL;
}

/*
 * ipcon_free_handler
 * Free an ipcon handler created by ipcon_create_handler().
 */
int ipcon_free_handler(IPCON_HANDLER handler)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);

	if (!iph)
		return;

	ipcon_chan_destory(&iph->ctrl_chan);
	ipcon_chan_destory(&iph->chan);

	free(iph);
}

/*
 * ipcon_register_service
 *
 * Register a service point. A service must have a name.
 */

int ipcon_register_service(IPCON_HANDLER handler, char *name)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	void *hdr = NULL;
	int ret = 0;
	int srv_name_len;
	struct nlmsghdr *nlh = NULL;
	struct nl_msg *msg = NULL;
	struct nlattr *tb[NUM_IPCON_ATTR];

	if (!iph || !name)
		return -EINVAL;

	srv_name_len = (int)strlen(name);
	if (!srv_name_len || srv_name_len > IPCON_MAX_SRV_NAME_LEN)
		return -EINVAL;

	ipcon_ctrl_lock(iph);

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_SRV_REG);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		ipcon_com_lock(iph);
		nla_put_u32(msg, IPCON_ATTR_PORT, iph->chan.port);
		ipcon_com_unlock(iph);
		nla_put_string(msg, IPCON_ATTR_SRV_NAME, name);

		ret = ipcon_send_msg(&iph->ctrl_chan, 0, msg, 1);
		nlmsg_free(msg);

		if (!ret)
			ret = ipcon_rcv_msg(&iph->ctrl_chan,
					0, IPCON_SRV_REG, NULL);
	} while (0);

	ipcon_ctrl_unlock(iph);

	return ret;
}

int ipcon_register_group(IPCON_HANDLER handler, char *name)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	void *hdr = NULL;
	int ret = 0;
	int grp_name_len;
	struct nlmsghdr *nlh = NULL;
	struct nl_msg *msg = NULL;
	struct nlattr *tb[NUM_IPCON_ATTR];

	if (!iph || !name)
		return -EINVAL;

	grp_name_len = (int)strlen(name);
	if (!grp_name_len || grp_name_len > IPCON_MAX_GRP_NAME_LEN)
		return -EINVAL;


	ipcon_ctrl_lock(iph);

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}
		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_GRP_REG);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_u32(msg, IPCON_ATTR_PORT, iph->ctrl_chan.port);
		nla_put_string(msg, IPCON_ATTR_GRP_NAME, name);

		ret = ipcon_send_msg(&iph->ctrl_chan, 0, msg, 1);
		nlmsg_free(msg);

		if (!ret)
			ret = ipcon_rcv_msg(&iph->ctrl_chan,
					0, IPCON_GRP_REG, NULL);
	} while (0);

	ipcon_ctrl_unlock(iph);

	return ret;
}

/*
 * ipcon_unregister_service
 *
 * Remove service registration. this make service point be an anonymous one.
 */

int ipcon_unregister_service(IPCON_HANDLER handler, char *name)
{
	int ret = 0;
	int srv_name_len;
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	struct nl_msg *msg = NULL;

	if (!iph || !name)
		return -EINVAL;

	srv_name_len = (int)strlen(name);
	if (!srv_name_len || srv_name_len > IPCON_MAX_SRV_NAME_LEN)
		return -EINVAL;

	ipcon_ctrl_lock(iph);

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_SRV_UNREG);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_SRV_NAME, name);

		ret = ipcon_send_msg(&iph->ctrl_chan, 0, msg, 1);
		nlmsg_free(msg);

		if (!ret)
			ret = ipcon_rcv_msg(&iph->ctrl_chan,
						0, IPCON_SRV_UNREG, NULL);
	} while (0);

	ipcon_ctrl_unlock(iph);

	return ret;
}

/*
 * ipcon_find_service
 *
 * Reslove the information of a service point by name.
 * If another message is received when waiting for resloving message from
 * kernel, queue it into the message queue.
 *
 */
int ipcon_find_service(IPCON_HANDLER handler, char *name, __u32 *srv_port)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	void *hdr = NULL;
	int ret = 0;
	int srv_name_len;
	struct nlmsghdr *nlh = NULL;
	struct nl_msg *msg = NULL;
	struct nlattr *tb[NUM_IPCON_ATTR];

	ipcon_dbg("%s enter.\n", __func__);

	if (!iph || !name)
		return -EINVAL;

	srv_name_len = (int)strlen(name);
	if (!srv_name_len || srv_name_len > IPCON_MAX_SRV_NAME_LEN)
		return -EINVAL;


	ipcon_ctrl_lock(iph);
	do {

		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_SRV_RESLOVE);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_SRV_NAME, name);

		ret = ipcon_send_msg(&iph->ctrl_chan, 0, msg, 0);
		nlmsg_free(msg);

		if (ret < 0) {
			ipcon_err("IPCON_SRV_RESLOVE cmd failed.\n");
			break;
		}

		/*
		 * IPCON_SRV_RESLOVE command is sent without NLM_ACK flag.
		 * there will not be nlerror come if no error happens.
		 * if service found, a reply message with portid set in
		 * IPCON_ATTR_PORT, if service not found, IPCON_ATTR_PORT will
		 * not exist.
		 */
		ret = ipcon_rcv_msg(&iph->ctrl_chan,
				0,
				IPCON_SRV_RESLOVE,
				&msg);
		if (ret < 0) {
			ipcon_err("IPCON_SRV_RESLOVE response failed.\n");
			break;
		}

		nlh = nlmsg_hdr(msg);
		ret = genlmsg_parse(nlh,
				IPCON_HDR_SIZE,
				tb,
				IPCON_ATTR_MAX,
				ipcon_policy);

		if (ret < 0) {
			ret = libnl_error(ret);
			ipcon_dbg("%s msg parse error with%d\n", __func__, ret);
			break;
		}

		if (tb[IPCON_ATTR_PORT])
			*srv_port = nla_get_u32(tb[IPCON_ATTR_PORT]);
		else
			ret = -ENOENT;


		nlmsg_free(msg);

	} while (0);

	ipcon_ctrl_unlock(iph);

	ipcon_dbg("%s exit with %d\n", __func__, ret);

	return ret;
}

static int ipcon_get_group(struct ipcon_peer_handler *iph, char *name,
		__u32 *groupid, struct nl_msg **rmsg)
{
	void *hdr = NULL;
	int ret = 0;
	int srv_name_len;
	struct nlmsghdr *nlh = NULL;
	struct nl_msg *msg = NULL;
	struct nlattr *tb[NUM_IPCON_ATTR];

	ipcon_dbg("%s enter.\n", __func__);

	do {

		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_GRP_RESLOVE);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_GRP_NAME, name);

		ret = ipcon_send_msg(&iph->ctrl_chan, 0, msg, 0);
		nlmsg_free(msg);

		if (ret < 0) {
			ipcon_err("IPCON_GRP_RESLOVE cmd failed.\n");
			break;
		}

		/*
		 * IPCON_GRP_RESLOVE command is sent without NLM_ACK flag.
		 * there will not be nlerror come if no error happens.
		 * if group found, a reply message with portid set in
		 * IPCON_ATTR_GROUP, if service not found, IPCON_ATTR_GROUP will
		 * not exist.
		 */
		ret = ipcon_rcv_msg(&iph->ctrl_chan,
				0,
				IPCON_GRP_RESLOVE,
				&msg);
		if (ret < 0) {
			ipcon_err("IPCON_GRP_RESLOVE response failed.\n");
			break;
		}

		nlh = nlmsg_hdr(msg);
		ret = genlmsg_parse(nlh,
				IPCON_HDR_SIZE,
				tb,
				IPCON_ATTR_MAX,
				ipcon_policy);

		if (ret < 0) {
			ret = libnl_error(ret);
			ipcon_dbg("%s msg parse error with%d\n", __func__, ret);
			break;
		}

		if (!tb[IPCON_ATTR_GROUP]) {
			ret = -ENOENT;
			break;
		}

		*groupid = nla_get_u32(tb[IPCON_ATTR_GROUP]);

	} while (0);

	nlmsg_free(msg);

	ipcon_dbg("%s exit with %d\n", __func__, ret);

	return ret;
}

/*
 * ipcon_join_group
 *
 * Suscribe an existed multicast group.
 * If a group has not been created, return as error.
 *
 * rcv_last_msg:
 *	if set to non-zero value, the last group message will be queued for
 *	reading. This is for multicast message that represent a state.
 */
int ipcon_join_group(IPCON_HANDLER handler, char *name, int rcv_last_msg)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	int ret = 0;
	struct nl_msg *msg = NULL;
	int srv_name_len = 0;
	__u32 groupid = 0;

	if (!iph || !name)
		return -EINVAL;

	srv_name_len = (int)strlen(name);
	if (!srv_name_len || srv_name_len > IPCON_MAX_GRP_NAME_LEN)
		return -EINVAL;

	ipcon_ctrl_lock(iph);

	do {
		ret = ipcon_get_group(iph, name, &groupid, &msg);
		if (ret < 0)
			break;

		ipcon_com_lock(iph);
		ret = nl_socket_add_memberships(iph->chan.sk,
					(int)groupid, 0);
		if (msg) {
			if (rcv_last_msg)
				queue_msg(&iph->chan.mq, msg);
			else
				nlmsg_free(msg);
		}

		ipcon_com_unlock(iph);

	} while (0);

	ipcon_ctrl_unlock(iph);

	if (!ret)
		ret = (int) groupid;

	return ret;
}

int ipcon_unregister_group(IPCON_HANDLER handler, char *name)
{
	int ret = 0;
	int grp_name_len;
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	struct nl_msg *msg = NULL;

	if (!iph || !name)
		return -EINVAL;

	grp_name_len = (int)strlen(name);
	if (!grp_name_len || grp_name_len > IPCON_MAX_GRP_NAME_LEN)
		return -EINVAL;

	ipcon_ctrl_lock(iph);

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_GRP_UNREG);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_GRP_NAME, name);

		ret = ipcon_send_msg(&iph->ctrl_chan, 0, msg, 1);
		nlmsg_free(msg);

		if (!ret)
			ret = ipcon_rcv_msg(&iph->ctrl_chan,
						0, IPCON_GRP_UNREG, NULL);
	} while (0);

	ipcon_ctrl_unlock(iph);

	return ret;
}

/*
 * ipcon_rcv
 *
 * Messages maybe received from
 * - Previously received messages which have been saved in the queue.
 * - Receive from remote point.
 *
 * if there is a message, ipcon_rcv() will return it immediately.
 * Otherwise, block until a message is coming.
 *
 * TODO: Non-block I/O implementation needed.
 */

int ipcon_rcv(IPCON_HANDLER handler, __u32 *port,
	unsigned int *group, __u32 *type, void **buf)
{
	int ret = 0;
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	struct nl_msg *msg = NULL;

	if (!iph)
		return -EINVAL;

	ipcon_com_lock(iph);
	do {
		struct nlmsghdr *nlh = NULL;
		struct nlattr *tb[NUM_IPCON_ATTR];
		int len;

		ret = ipcon_rcv_msg(&iph->chan,
				IPCON_ANY_PORT,
				IPCON_USR_MSG,
				&msg);
		if (ret < 0)
			break;


		nlh = nlmsg_hdr(msg);
		ret = genlmsg_parse(nlh,
				IPCON_HDR_SIZE,
				tb,
				IPCON_ATTR_MAX,
				ipcon_policy);

		if (ret < 0) {
			ret = libnl_error(ret);
			break;
		}

		if (!tb[IPCON_ATTR_MSG_TYPE]) {
			ret = -EREMOTEIO;
			break;
		}

		if (!tb[IPCON_ATTR_DATA]) {
			ret = -EREMOTEIO;
			break;
		}

		*type = nla_get_u32(tb[IPCON_ATTR_MSG_TYPE]);
		if (*type == IPCON_MSG_UNICAST) {

			if (!tb[IPCON_ATTR_PORT]) {
				ret = -EREMOTEIO;
				break;
			}

			*port = nla_get_u32(tb[IPCON_ATTR_PORT]);

		} else if (*type == IPCON_MSG_MULTICAST) {

			if (!tb[IPCON_ATTR_GROUP]) {
				ret = -EREMOTEIO;
				break;
			}

			*group = nla_get_u32(tb[IPCON_ATTR_GROUP]);

		} else {
			ret = -EREMOTEIO;
		}


		len = nla_len(tb[IPCON_ATTR_DATA]);
		*buf = malloc((size_t)len);
		if (!*buf) {
			ret = -ENOMEM;
			break;
		}

		memcpy(*buf, nla_data(tb[IPCON_ATTR_DATA]), (size_t)len);
		ret = len;

	} while (0);

	nlmsg_free(msg);
	ipcon_com_unlock(iph);

	return ret;
}

/*
 * ipcon_send_unicast
 *
 * Send message to a specific port.
 */

int ipcon_send_unicast(IPCON_HANDLER handler, __u32 port,
				void *buf, size_t size)
{

	int ret = 0;
	struct nl_msg *msg = NULL;
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	struct nl_data *nldata;

	if (!iph || (size <= 0) || (size > IPCON_MAX_MSG_LEN))
		return -EINVAL;

	/* Appli is not permitted to send a msg to kernel */
	if (!port)
		return -EINVAL;

	ipcon_com_lock(iph);

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->chan, 0, IPCON_USR_MSG);

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_u32(msg, IPCON_ATTR_PORT, iph->chan.port);
		nldata = nl_data_alloc(buf, size);
		nla_put_data(msg, IPCON_ATTR_DATA, nldata);

		ret = ipcon_send_msg(&iph->chan, port, msg, 0);

	} while (0);

	nlmsg_free(msg);
	ipcon_com_unlock(iph);

	return ret;
}

/*
 * ipcon_send_multicast
 *
 * Send a message to the own service group. No care whether message is
 * deliveried to the receiver or not (even if there is not a receiver).
 *
 */

int ipcon_send_multicast(IPCON_HANDLER handler, void *buf, size_t size)
{
}

/*
 * ipcon_leave_group
 *
 * Unsuscribe a multicast group.
 *
 */
int ipcon_leave_group(IPCON_HANDLER handler, __u32 groupid)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	int ret = 0;

	if (!iph)
		return -EINVAL;

	ipcon_com_lock(iph);
	ret = nl_socket_drop_membership(iph->chan.sk, (int)groupid);
	ipcon_com_unlock(iph);

	return ret;

}

/*
 * ipcon_get_selfport
 *
 * Get sefl port number.
 */

__u32 ipcon_get_selfport(IPCON_HANDLER handler)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	__u32 port;

	if (!iph)
		return 0;

	ipcon_com_lock(iph);
	port = iph->chan.port;
	ipcon_com_unlock(iph);

	return port;
}

/*
 * ipcon_getfd
 *
 * Return the socket fd for user to do select(), poll() and etc.
 */

int ipcon_getfd(IPCON_HANDLER handler)
{
}
