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
	struct ipcon_peer_handler *iph;
	__u32 target_port;
	int target_cmd;
	struct nl_msg *msg;
};


static struct nla_policy ipcon_policy[NUM_IPCON_ATTR] = {
	[IPCON_ATTR_MSG_TYPE] = {.type = NLA_U32},
	[IPCON_ATTR_PORT] = {.type = NLA_U32},
	[IPCON_ATTR_SRV_NAME] = {.type = NLA_NUL_STRING,
				.maxlen = IPCON_MAX_SRV_NAME_LEN - 1 },
	[IPCON_ATTR_SRV_GROUP] = {.type = NLA_U32},
	[IPCON_ATTR_DATA] = {.type = NLA_BINARY, .maxlen = IPCON_MAX_MSG_LEN},
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

	if (!irmi || !irmi->iph) {
		ipcon_err("valid msg losted for null handler.\n");
		return -EINVAL;
	}

	if (nlh->nlmsg_type != irmi->iph->ipcon_family)
		return NL_SKIP;

	nlmsg_get(msg);

	if (rcvmsg_match_cond(msg, irmi->target_port, irmi->target_cmd))
		irmi->msg = msg;
	else
		queue_msg(&irmi->iph->mq, msg);

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

static int ipcon_rcv_msg(struct ipcon_peer_handler *iph,
			__u32 target_port, int target_cmd, struct nl_msg **pmsg)
{

	struct ipcon_rcv_msg_info irmi;
	struct nl_msg *msg = NULL;
	int ret = 0;

	if (!iph)
		return -EINVAL;

	msg = dequeue_msg_cond(&iph->mq, target_port, target_cmd);
	if (msg) {
		if (pmsg)
			*pmsg = msg;
		return 0;
	}

	irmi.iph = iph;
	irmi.target_port = target_port;
	irmi.target_cmd = target_cmd;
	irmi.msg = NULL;

	nl_socket_modify_cb(iph->sk,
			NL_CB_VALID,
			NL_CB_CUSTOM,
			valid_msg_cb,
			(void *)&irmi);

	ret = nl_recvmsgs_default(iph->sk);
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

static int ipcon_send_msg(struct ipcon_peer_handler *iph, struct nl_msg *msg)
{
	int ret = 0;

	if (!iph)
		return -EINVAL;

	ret = nl_send_auto(iph->sk, msg);
	if (ret >= 0)
		ret = 0;
	else
		ret = libnl_error(ret);

	return ret;
}

/*
 * ipcon_create_handler
 * Create and return a ipcon handler with an internal structure ipcon_mng_info.
 */

IPCON_HANDLER ipcon_create_handler(void)
{
	struct ipcon_peer_handler *iph = NULL;
	int gi = 0;
	int ret = 0;

	pthread_mutexattr_t mtxAttr;

	if (pthread_mutexattr_init(&mtxAttr))
		return NULL;

#ifdef __DEBUG__
	if (pthread_mutexattr_settype(&mtxAttr,
				PTHREAD_MUTEX_ERRORCHECK))
		return NULL;
#else
	if (pthread_mutexattr_settype(&mtxAttr,
				PTHREAD_MUTEX_NORMAL))
		return NULL;
#endif


	iph = malloc(sizeof(*iph));
	if (!iph)
		return NULL;

	do {

		for (gi = 0; gi < IPCON_MAX_USR_GROUP; gi++) {
			iph->grp[gi].groupid = 0;
			iph->grp[gi].name[0] = '\0';
		}

		iph->srv.name[0] = '\0';

		if (pthread_mutex_init(&iph->mutex, &mtxAttr))
			break;

		iph->sk = nl_socket_alloc();
		if (!iph->sk)
			break;

		ret = genl_connect(iph->sk);
		if (ret < 0)
			break;

		iph->ipcon_family = genl_ctrl_resolve(iph->sk, IPCON_GENL_NAME);
		if (iph->ipcon_family < 0) {
			iph->ipcon_family = 0;
			break;
		}

		/* We don't required a ACK by default */
		nl_socket_disable_auto_ack(iph->sk);

		return iph_to_handler(iph);

	} while (0);

	/* NULL is ok for nl_socket_free() */
	nl_socket_free(iph->sk);
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

	pthread_mutex_destroy(&iph->mutex);

	close(iph->sk);
	free(iph);
}

static inline int find_empty_grop_slot(struct ipcon_peer_handler *iph)
{
	int i;

	for (i = 0; i < IPCON_MAX_USR_GROUP; i++)
		if (!iph->grp[i].groupid)
			return i;

	return -1;
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

	pthread_mutex_lock(&iph->mutex);

	do {
		if (iph->srv.name) {
			ret = -EEXIST;
			break;
		}

		iph->srv.name = malloc(IPCON_MAX_SRV_NAME_LEN);
		if (!iph->srv.name) {
			ret = -ENOMEM;
			break;
		}

		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		genlmsg_put(msg, 0, 0, iph->ipcon_family,
				IPCON_HDR_SIZE, 0, IPCON_SRV_REG, 1);

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_SRV_NAME, name);

		/* Use nlerr to judge sucess or fail */
		nl_socket_enable_auto_ack(iph->sk);

		ret = ipcon_send_msg(iph, msg);

		nl_socket_disable_auto_ack(iph->sk);
		nlmsg_free(msg);

		if (!ret)
			ret = ipcon_rcv_msg(iph, 0, IPCON_SRV_REG, NULL);
	} while (0);

	if (ret < 0) {
		if (iph->srv.name) {
			free(iph->srv.name);
			iph->srv.name = NULL;
		}
	} else {
		strcpy(iph->srv.name, name);
	}

	pthread_mutex_unlock(&iph->mutex);

	return ret;
}


/*
 * ipcon_unregister_service
 *
 * Remove service registration. this make service point be an anonymous one.
 */

int ipcon_unregister_service(IPCON_HANDLER handler)
{
	int ret = 0;
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	struct nl_msg *msg = NULL;

	if (!iph)
		return -EINVAL;

	pthread_mutex_lock(&iph->mutex);

	do {
		if (!iph->srv.name) {
			ret = -EINVAL;
			break;
		}

		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		genlmsg_put(msg, 0, 0, iph->ipcon_family,
				IPCON_HDR_SIZE, 0, IPCON_SRV_UNREG, 1);

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_SRV_NAME, iph->srv.name);

		/* Use nlerr to judge sucess or fail */
		nl_socket_enable_auto_ack(iph->sk);

		ret = ipcon_send_msg(iph, msg);

		nl_socket_disable_auto_ack(iph->sk);
		nlmsg_free(msg);

		if (!ret)
			ret = ipcon_rcv_msg(iph, 0, IPCON_SRV_UNREG, NULL);

		if (!ret) {
			free(iph->srv.name);
			iph->srv.name = NULL;
		}

	} while (0);

	pthread_mutex_unlock(&iph->mutex);

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
int ipcon_find_service(IPCON_HANDLER handler, char *name, __u32 *srv_port,
		unsigned int *group)
{
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
			unsigned int *group, void **buf)
{
}

/*
 * ipcon_send_unicast
 *
 * Send message to a specific port.
 */

int ipcon_send_unicast(IPCON_HANDLER handler, __u32 port,
				void *buf, size_t size)
{
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
 * ipcon_join_group
 *
 * Suscribe an existed multicast group.
 * If a group has not been created, return as error.
 *
 * rcv_last_msg:
 *	if set to non-zero value, the last group message will be queued for
 *	reading. This is for multicast message that represent a state.
 */
int ipcon_join_group(IPCON_HANDLER handler, unsigned int group,
			int rcv_last_msg)
{
}

/*
 * ipcon_leave_group
 *
 * Unsuscribe a multicast group.
 *
 */
int ipcon_leave_group(IPCON_HANDLER handler, unsigned int group)
{
}

/*
 * ipcon_get_selfport
 *
 * Get sefl port number.
 */

__u32 ipcon_get_selfport(IPCON_HANDLER handler)
{
}

/*
 * ipcon_get_selfsrv
 *
 * Get the information of service registerred by self.
 */

struct ipcon_srv *ipcon_get_selfsrv(IPCON_HANDLER handler)
{
}

/*
 * ipcon_getfd
 *
 * Return the socket fd for user to do select(), poll() and etc.
 */

int ipcon_getfd(IPCON_HANDLER handler)
{
}
