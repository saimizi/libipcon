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
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <pthread.h>
#include <time.h>

#include "libipcon_dbg.h"
#include "libipcon_priv.h"

struct ipcon_nl_data {
	size_t	d_size;
	void	*d_data;
};

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

static struct nla_policy ipcon_policy[NUM_IPCON_ATTR] = {
	[IPCON_ATTR_MSG_TYPE] = {.type = NLA_U32},
	[IPCON_ATTR_PORT] = {.type = NLA_U32},
	[IPCON_ATTR_GROUP] = {.type = NLA_U32},
	[IPCON_ATTR_GRP_NAME] = {.type = NLA_NUL_STRING,
				.maxlen = IPCON_MAX_NAME_LEN - 1 },
	[IPCON_ATTR_DATA] = {.type = NLA_BINARY, .maxlen = IPCON_MAX_MSG_LEN},
	[IPCON_ATTR_FLAG] = {.type = NLA_FLAG},
	[IPCON_ATTR_PEER_NAME] = {.type = NLA_NUL_STRING,
				.maxlen = IPCON_MAX_NAME_LEN - 1 },
	[IPCON_ATTR_SRC_PEER] = {.type = NLA_NUL_STRING,
				.maxlen = IPCON_MAX_NAME_LEN - 1 },
};

static inline void *ipcon_put(struct nl_msg *msg, struct ipcon_channel *ic,
		int flags, uint8_t cmd)
{
	return genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ic->family,
			IPCON_HDR_SIZE, flags, cmd, 1);
};

/*
 * ipcon_rcv_msg
 */

static int ipcon_rcv_msg(struct ipcon_channel *ic, struct nl_msg **nlh,
		int wait_ack)
{
	int ret = 0;
	struct nlmsghdr *lnlh = NULL;
	struct sockaddr_nl from;
	struct ucred *creds;

	do {
		if (!ic) {
			ret = -EINVAL;
			break;
		}

		memset(&from, 0, sizeof(from));

		ret = nl_recv(ic->sk, &from, (unsigned char **)&lnlh, &creds);
		if  (ret < 0) {
			ret = libnl_error(ret);
			break;
		}

		ret = 0;

		if (lnlh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = nlmsg_data(lnlh);

			ret = e->error;
#if DEBUG_ACK
			{
				struct genlmsghdr *gnlh = nlmsg_data(&e->msg);

				ipcon_dbg("NLMSG_ERROR: ret = %d cmd=%d\n",
					ret, gnlh->cmd);
			}
#endif

			break;
		}

		if (nlh) {
			*nlh = nlmsg_convert(lnlh);
			if (!*nlh) {
				ret = -ENOMEM;
				break;
			}

			nlmsg_set_src(*nlh, &from);
			if (creds)
				nlmsg_set_creds(*nlh, creds);
		} else {
			struct genlmsghdr *gnlh = nlmsg_data(lnlh);

			ipcon_warn("Message received (cmd: %d) dopped!\n",
					gnlh->cmd);
		}

		if (!wait_ack)
			break;

	} while (1);

	if (lnlh)
		free(lnlh);

	return ret;
}

static int ipcon_send_msg(struct ipcon_channel *ic, __u32 port,
			struct nl_msg *msg)
{
	int ret = 0;
	struct sockaddr_nl dst;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	dst.nl_pid = port;
	dst.nl_groups = 0;
	nlmsg_set_dst(msg, &dst);

	ret = nl_send_auto(ic->sk, msg);
	if (ret < 0)
		ret = libnl_error(ret);
	else
		ret = 0;

	return ret;
}

static int ipcon_send_rcv_msg(struct ipcon_channel *ic, __u32 port,
			struct nl_msg *msg, struct nl_msg **ack)
{
	int ret = 0;

	do {
		ret = ipcon_send_msg(ic, port, msg);
		if (ret < 0)
			break;

		ret = ipcon_rcv_msg(ic, ack, 1);

	} while (0);

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
	ic->family = 0;
	pthread_mutex_destroy(&ic->mutex);
};

static char *auto_peer_name()
{
	int rnum = 0;
	char *name = malloc(IPCON_MAX_NAME_LEN);
	struct timeval tv;

	gettimeofday(&tv, NULL);

#if IPCON_MAX_NAME_LEN >= 13

	if (!name)
		return NULL;

	srand((unsigned int)tv.tv_usec);
	rnum = rand() % (9999999 - 1 + 1) + 1;
	sprintf(name, "Anon-%lu", (unsigned long)rnum);
#else
#error "IPCON_MAX_NAME_LEN is too small."
#endif

	return name;
}

/*
 * ipcon_create_handler
 * Create and return a ipcon handler with an internal structure ipcon_mng_info.
 */

IPCON_HANDLER ipcon_create_handler(char *peer_name, enum peer_type type)
{
	struct ipcon_peer_handler *iph = NULL;
	int gi = 0;
	int ret = 0;
	size_t name_len = 0;
	char *name = NULL;


	do {
		int i;
		int family;
		struct nl_msg *msg = NULL;

		if (!peer_name)
			name = auto_peer_name();
		else
			name = strdup(peer_name);

		if (!valid_peer_name(name))
			break;

		ipcon_dbg("Peer name: %s\n", name);

		iph = malloc(sizeof(*iph));
		if (!iph)
			break;

		if (ipcon_chan_init(&iph->chan))
			break;

		ipcon_dbg("Comm port: %lu.\n",
				(unsigned long)iph->chan.port);

		if (ipcon_chan_init(&iph->ctrl_chan))
			break;
		ipcon_dbg("Ctrl port: %lu.\n",
				(unsigned long)iph->ctrl_chan.port);

		family = genl_ctrl_resolve(iph->ctrl_chan.sk, IPCON_NAME);
		if (family < 0)
			break;

		iph->ctrl_chan.family = iph->chan.family = family;
		lh_init(&iph->grp);

		/* We don't required a ACK by default */
		nl_socket_disable_auto_ack(iph->chan.sk);
		nl_socket_enable_auto_ack(iph->ctrl_chan.sk);

		/* Register peer
		 * The aim is to increase the ipcon driver reference counter so
		 * that it will not be rmmoded while in use.
		 * No need to unregister, because ipcon driver is able to detect
		 * the removal of the peer itself and descrease the reference
		 * counter automically.
		 */
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_PEER_REG);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_u32(msg, IPCON_ATTR_PORT, iph->chan.port);
		nla_put_u32(msg, IPCON_ATTR_PEER_TYPE, type);
		nla_put_string(msg, IPCON_ATTR_PEER_NAME, name);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv_msg(&iph->ctrl_chan, 0, msg, NULL);
		ipcon_ctrl_unlock(iph);
		nlmsg_free(msg);

		if (ret < 0)
			break;

		iph->name = name;

		return iph_to_handler(iph);

	} while (0);

	/* NULL is ok for ipcon_chan_destory() */
	ipcon_chan_destory(&iph->chan);
	ipcon_chan_destory(&iph->ctrl_chan);
	free(iph);

	if (name)
		free(name);

	return NULL;
}

/*
 * ipcon_free_handler
 * Free an ipcon handler created by ipcon_create_handler().
 */
void ipcon_free_handler(IPCON_HANDLER handler)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);

	if (!iph)
		return;

	ipcon_chan_destory(&iph->ctrl_chan);
	ipcon_chan_destory(&iph->chan);
	free(iph->name);

	free(iph);
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
	if (!grp_name_len || grp_name_len > IPCON_MAX_NAME_LEN)
		return -EINVAL;

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}
		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_GRP_REG);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_GRP_NAME, name);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv_msg(&iph->ctrl_chan, 0, msg, NULL);
		ipcon_ctrl_unlock(iph);
		nlmsg_free(msg);

	} while (0);


	return ret;
}

int is_peer_present(IPCON_HANDLER handler, char *name)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	void *hdr = NULL;
	int ret = 0;
	int srv_name_len;
	struct nlmsghdr *nlh = NULL;
	struct nl_msg *msg = NULL;
	struct nl_msg *rmsg = NULL;
	struct nlattr *tb[NUM_IPCON_ATTR];

	if (!iph)
		return -EINVAL;

	if (!valid_peer_name(name))
		return -EINVAL;


	do {

		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_PEER_RESLOVE);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_PEER_NAME, name);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv_msg(&iph->ctrl_chan, 0, msg, &rmsg);
		ipcon_ctrl_unlock(iph);
		nlmsg_free(msg);

		if (ret < 0)
			break;

		nlh = nlmsg_hdr(rmsg);
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

		if (tb[IPCON_ATTR_FLAG])
			ret = 1;
		else
			ret = 0;

		nlmsg_free(rmsg);

	} while (0);

	return ret;
}

static int ipcon_get_group(struct ipcon_peer_handler *iph, char *srvname,
		char *grpname, __u32 *groupid, int rcv_last_msg)
{
	void *hdr = NULL;
	int ret = 0;
	int srv_name_len;
	struct nlmsghdr *nlh = NULL;
	struct nl_msg *msg = NULL;
	struct nl_msg *rmsg = NULL;
	struct nlattr *tb[NUM_IPCON_ATTR];

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_GRP_RESLOVE);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_SRV_NAME, srvname);
		nla_put_string(msg, IPCON_ATTR_GRP_NAME, grpname);
		if (rcv_last_msg)
			nla_put_flag(msg, IPCON_ATTR_FLAG);

		ret = ipcon_send_rcv_msg(&iph->ctrl_chan, 0, msg, &rmsg);
		nlmsg_free(msg);

		if (ret < 0)
			break;

		nlh = nlmsg_hdr(rmsg);
		ret = genlmsg_parse(nlh,
				IPCON_HDR_SIZE,
				tb,
				IPCON_ATTR_MAX,
				ipcon_policy);

		if (ret < 0) {
			ret = libnl_error(ret);
			break;
		}

		if (!tb[IPCON_ATTR_GROUP]) {
			ret = -ENOENT;
			break;
		}

		*groupid = nla_get_u32(tb[IPCON_ATTR_GROUP]);
		nlmsg_free(rmsg);
	} while (0);

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
int ipcon_join_group(IPCON_HANDLER handler, char *srvname, char *grpname,
		int rcv_last_msg)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	int ret = 0;
	int srv_name_len = 0;
	int grp_name_len = 0;
	__u32 groupid = 0;

	if (!iph || !srvname || !grpname)
		return -EINVAL;

	srv_name_len = (int)strlen(srvname);
	grp_name_len = (int)strlen(grpname);

	if (!srv_name_len || srv_name_len > IPCON_MAX_NAME_LEN)
		return -EINVAL;

	if (!grp_name_len || grp_name_len > IPCON_MAX_NAME_LEN)
		return -EINVAL;

	ipcon_ctrl_lock(iph);
	do {
		struct ipcon_group_info *igi = NULL;

		igi = malloc(sizeof(*igi));
		if (!igi) {
			ret = -ENOMEM;
			break;
		}

		le_init(&igi->le);

		ret = ipcon_get_group(iph, srvname, grpname,
				&groupid, rcv_last_msg);

		if (ret < 0) {
			free(igi);
			break;
		}

		igi->groupid = groupid;
		strcpy(igi->grpname, grpname);
		strcpy(igi->srvname, srvname);
		le_addtail(LINK_ENTRY_HEAD(iph), LINK_ENTRY(igi));

		ret = nl_socket_add_memberships(iph->chan.sk,
					(int)groupid, 0);
		if (ret < 0) {
			le_remove(LINK_ENTRY(igi));
			free(igi);
		}

	} while (0);
	ipcon_ctrl_unlock(iph);

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
	if (!grp_name_len || grp_name_len > IPCON_MAX_NAME_LEN)
		return -EINVAL;


	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_GRP_UNREG);
		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_GRP_NAME, name);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv_msg(&iph->ctrl_chan, 0, msg, NULL);
		ipcon_ctrl_unlock(iph);
		nlmsg_free(msg);

	} while (0);


	return ret;
}

/*
 * ipcon_send_unicast
 *
 * Send message to a specific port.
 */

int ipcon_send_unicast(IPCON_HANDLER handler, char *name,
				void *buf, size_t size)
{

	int ret = 0;
	struct nl_msg *msg = NULL;
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	struct ipcon_nl_data ipcon_data;

	if (!iph || (size <= 0) || (size > IPCON_MAX_MSG_LEN))
		return -EINVAL;

	if (!valid_peer_name(name))
		return -EINVAL;

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->chan, 0, IPCON_USR_MSG);

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_string(msg, IPCON_ATTR_PEER_NAME, name);
		nla_put_string(msg, IPCON_ATTR_SRC_PEER, iph->name);
		ipcon_data.d_size = size;
		ipcon_data.d_data = buf;
		nla_put_data(msg, IPCON_ATTR_DATA,
			(struct nl_data *)&ipcon_data);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv_msg(&iph->ctrl_chan, 0, msg, NULL);
		ipcon_ctrl_unlock(iph);

	} while (0);

	nlmsg_free(msg);

	return ret;
}

/*
 * ipcon_send_multicast
 *
 * Send a message to the own service group. No care whether message is
 * deliveried to the receiver or not (even if there is not a receiver).
 *
 */

int ipcon_send_multicast(IPCON_HANDLER handler, char *name, void *buf,
			size_t size, int sync)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	int ret = 0;
	struct ipcon_nl_data ipcon_data;

	if (!iph || !name || !buf)
		return -EINVAL;

	if (strlen(name) > IPCON_MAX_NAME_LEN)
		return -EINVAL;


	do {
		struct nl_msg *msg = NULL;

		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_put(msg, &iph->ctrl_chan, 0, IPCON_MULTICAST_MSG);

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_MULTICAST);
		nla_put_string(msg, IPCON_ATTR_GRP_NAME, name);
		if (sync)
			nla_put_flag(msg, IPCON_ATTR_FLAG);
		ipcon_data.d_size = size;
		ipcon_data.d_data = buf;
		nla_put_data(msg, IPCON_ATTR_DATA,
			(struct nl_data *)&ipcon_data);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv_msg(&iph->ctrl_chan, 0, msg, NULL);
		ipcon_ctrl_unlock(iph);
		nlmsg_free(msg);

	} while (0);


	return ret;
}

/*
 * ipcon_leave_group
 *
 * Unsuscribe a multicast group.
 *
 */
int ipcon_leave_group(IPCON_HANDLER handler, char *srvname, char *grpname)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	struct ipcon_group_info *igi = NULL;
	int ret = 0;
	int groupid = -1;

	if (!iph || !grpname)
		return -EINVAL;

	ipcon_ctrl_lock(iph);
	for (igi = le_next(LINK_ENTRY(iph)); igi;
			igi = le_next(LINK_ENTRY(igi))) {
		if (!strcmp(igi->grpname, grpname) &&
			!strcmp(igi->srvname, srvname)) {
			break;
		}

	}

	if (igi) {
		ret = nl_socket_drop_membership(iph->chan.sk,
				(int)igi->groupid);
		if (!ret)
			le_remove(LINK_ENTRY(igi));
	}

	ipcon_ctrl_unlock(iph);
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

	return iph->chan.port;
}

/*
 * ipcon_getfd
 *
 * Return the socket fd for user to do select(), poll() and etc.
 */

int ipcon_getfd(IPCON_HANDLER handler)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);

	if (iph)
		return nl_socket_get_fd(iph->chan.sk);

	return -EBADF;
}

static int is_timeout(struct timeval *timeout)
{
	return (!timeout->tv_sec) && (!timeout->tv_usec);
}

#define WAIT_TIME_USEC	1000	/* 1ms */
static void update_timeout(struct timeval *timeout)
{
	if (timeout->tv_usec > WAIT_TIME_USEC) {
		timeout->tv_usec -= WAIT_TIME_USEC;
	} else {
		if (timeout->tv_sec) {
			timeout->tv_usec += 1000000 - WAIT_TIME_USEC;
			timeout->tv_sec--;
		} else {
			timeout->tv_sec = 0;
			timeout->tv_usec = 0;
		}
	}
}

int ipcon_rcv_timeout(IPCON_HANDLER handler, struct ipcon_msg *im,
		struct timeval *timeout)
{
	int ret = 0;
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	struct nl_msg *msg = NULL;

	if (!iph || !im)
		return -EINVAL;

	do {
		int fd = nl_socket_get_fd(iph->chan.sk);
		struct nlmsghdr *nlh = NULL;
		struct nlattr *tb[NUM_IPCON_ATTR];
		int len;
		fd_set rfds;

		if (timeout) {
			ret = ipcon_com_trylock(iph);
			if (ret) {
				do {
					update_timeout(timeout);
					if (is_timeout(timeout)) {
						ret = -ETIMEDOUT;
						break;
					}
					usleep(WAIT_TIME_USEC);

					ret = ipcon_com_trylock(iph);
					if (!ret)
						break;
				} while (1);

				if (ret)
					break;
			}
		} else {
			ipcon_com_lock(iph);
		}

		if (timeout) {
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);

			ret = select(fd + 1, &rfds, NULL, NULL, timeout);
			if (!ret) {
				ipcon_com_unlock(iph);
				ret = -ETIMEDOUT;
				break;
			} else if (ret < 0) {
				ret = -errno;
				break;
			}
		}

		ret = ipcon_rcv_msg(&iph->chan, &msg, 0);

		ipcon_com_unlock(iph);

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

		im->type = nla_get_u32(tb[IPCON_ATTR_MSG_TYPE]);
		if (im->type == IPCON_MSG_UNICAST) {

			if (!tb[IPCON_ATTR_SRC_PEER]) {
				ret = -EREMOTEIO;
				break;
			}

			strcpy(im->group,
				nla_get_string(tb[IPCON_ATTR_SRC_PEER]));

		} else if (im->type == IPCON_MSG_MULTICAST) {

			if (!tb[IPCON_ATTR_GRP_NAME]) {
				ret = -EREMOTEIO;
				break;
			}

			strcpy(im->group,
				nla_get_string(tb[IPCON_ATTR_GRP_NAME]));
		} else {
			ret = -EREMOTEIO;
		}

		im->len = (__u32) nla_len(tb[IPCON_ATTR_DATA]);
		memcpy((void *)im->buf,
			nla_data(tb[IPCON_ATTR_DATA]),
			(size_t)im->len);


	} while (0);

	nlmsg_free(msg);

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
 * No lock needed
 * - no ctrl message will be recevived from the communication channel.
 * - read/write can be done simultaneously for socket.
 */

int ipcon_rcv(IPCON_HANDLER handler, struct ipcon_msg *im)
{
	return ipcon_rcv_timeout(handler, im, NULL);
}

int ipcon_rcv_nonblock(IPCON_HANDLER handler, struct ipcon_msg *im)
{
	struct timeval timeout;

	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	return ipcon_rcv_timeout(handler, im, &timeout);
}

const char *ipcon_selfname(IPCON_HANDLER handler)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);

	return (const char *)iph->name;
}
