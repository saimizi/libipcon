#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/errno.h>
#include <netlink/attr.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>

#include "libipcon_dbg.h"
#include "libipcon_priv.h"

void __attribute__ ((constructor)) libipcon_init(void)
{
	libipcon_dbg_init();
}

static struct nla_policy ipcon_policy[NUM_IPCON_ATTR] = {
	[IPCON_ATTR_CPORT] = {
		.type = NLA_U32,
	},

	[IPCON_ATTR_SPORT] = {
		.type = NLA_U32,
	},

	[IPCON_ATTR_RPORT] = {
		.type = NLA_U32,
	},

	[IPCON_ATTR_GROUP] = {
		.type = NLA_U32
	},

	[IPCON_ATTR_PEER_NAME] = {
		.type = NLA_NUL_STRING,
		.maxlen = IPCON_MAX_NAME_LEN - 1,
	},

	[IPCON_ATTR_GROUP_NAME] = {
		.type = NLA_NUL_STRING,
		.maxlen = IPCON_MAX_NAME_LEN - 1,
	},

	[IPCON_ATTR_DATA] = {
		.type = NLA_BINARY,
		.maxlen = MAX_IPCONMSG_DATA_SIZE,
	},

	[IPCON_ATTR_FLAG] = {
		.type = NLA_U32,
	},

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

IPCON_HANDLER ipcon_create_handler(char *peer_name, unsigned long flags)
{
	struct ipcon_peer_handler *iph = NULL;
	int gi = 0;
	int ret = -1;

	do {
		int i;
		int family;
		struct nl_msg *msg = NULL;


		iph = malloc(sizeof(*iph));
		if (!iph)
			break;

		memset(iph, 0, sizeof(*iph));

		if (peer_name) {
			iph->name = strdup(peer_name);
		} else {
			iph->flags |= IPH_FLG_ANON_PEER;
			iph->name = auto_peer_name();
		}

		if (flags & LIBIPCON_FLG_DISABLE_KEVENT_FILTER)
			iph->flags |= IPH_FLG_DISABLE_KEVENT_FILTER;

		ipcon_dbg("Peer name: %s\n", iph->name);

		if (ipcon_chan_init(iph))
			break;

		lh_init(&iph->grp);

		ret = 0;

	} while (0);

	if (ret < 0) {

		if (iph) {
			/* NULL is ok for ipcon_chan_destory() */
			ipcon_chan_destory(&iph->c_chan);
			ipcon_chan_destory(&iph->s_chan);
			ipcon_chan_destory(&iph->r_chan);
			free(iph);
			iph = NULL;
		}
	}

	return iph_to_handler(iph);
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

	ipcon_chan_destory(&iph->c_chan);
	ipcon_chan_destory(&iph->s_chan);
	ipcon_chan_destory(&iph->r_chan);
	free(iph->name);

	free(iph);
}

int ipcon_register_group(IPCON_HANDLER handler, char *name)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	void *hdr = NULL;
	int ret = 0;
	struct nlmsghdr *nlh = NULL;
	struct nl_msg *msg = NULL;
	struct nlattr *tb[NUM_IPCON_ATTR];

	if (!iph || !name)
		return -EINVAL;

	if (!valid_name(name))
		return -EINVAL;

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_c_lock(iph);
		ipconmsg_put(msg, &iph->c_chan, IPCON_GRP_REG, 0);
		nla_put_string(msg, IPCON_ATTR_GROUP_NAME, name);
		ipconmsg_complete(&iph->c_chan, msg);

		ret = ipcon_send_rcv(&iph->c_chan, msg, NULL);
		ipcon_c_unlock(iph);
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

	if (!valid_name(name))
		return -EINVAL;


	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_c_lock(iph);
		ipconmsg_put(msg, &iph->c_chan, IPCON_PEER_RESLOVE, 0);
		nla_put_string(msg, IPCON_ATTR_PEER_NAME, name);

		ret = ipcon_send_rcv(&iph->c_chan, msg, NULL);
		ipcon_c_unlock(iph);

	} while (0);

	return ret == 0;
}


static int ipcon_get_group(struct ipcon_peer_handler *iph, char *peer_name,
		char *group_name, __u32 *groupid)
{
	void *hdr = NULL;
	int ret = 0;
	int srv_name_len;
	struct nlmsghdr *nlh = NULL;
	struct nl_msg *msg = NULL;
	struct nl_msg *rmsg = NULL;

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

ipcon_dbg("Enter %s: peer_name: %s group_name: %s\n", iph->name, peer_name, group_name);

		ipconmsg_put(msg, &iph->c_chan,IPCON_GRP_RESLOVE,0);
		nla_put_string(msg, IPCON_ATTR_PEER_NAME, peer_name);
		nla_put_string(msg, IPCON_ATTR_GROUP_NAME, group_name);
		ipconmsg_complete(&iph->c_chan, msg);

		ret = ipcon_send_rcv(&iph->c_chan, msg, &rmsg);
		if (!ret) {
			struct nlattr  *group_attr;

			assert(rmsg);

			group_attr = ipcon_find_attr(rmsg, IPCON_ATTR_GROUP);
			assert(group_attr);

			if (groupid)
				*groupid = nla_get_u32(group_attr);

		}
	} while (0);

	nlmsg_free(rmsg);

ipcon_dbg("Leave%s: peer_name: %s group_name: %s groupid; %u\n", iph->name, peer_name, group_name, groupid ? *groupid : 0xFFFFFFFF);
	return ret;
}

int is_group_present(IPCON_HANDLER handler, char *peer_name, char *group_name)
{
	int ret = 0;
	struct ipcon_peer_handler *iph = handler_to_iph(handler);

	if (!iph || !valid_name(peer_name) || !valid_name(group_name))
		return -EINVAL;

	ipcon_c_lock(iph);
	ret = ipcon_get_group(iph, peer_name, group_name, NULL);
	ipcon_c_unlock(iph);

	return ret == 0;
}

/*
 * ipcon_join_group
 *
 * Suscribe an existed multicast group.
 * If a group has not been created, return as error.
 */
int ipcon_join_group(IPCON_HANDLER handler, char *peer_name, char *group_name)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	int ret = 0;
	__u32 groupid = 0;

	if (!iph)
		return -EINVAL;

	if (!valid_name(peer_name))
		return -EINVAL;

	if (!valid_name(group_name))
		return -EINVAL;

	do {
		struct ipcon_group_info *igi = NULL;

		igi = malloc(sizeof(*igi));
		if (!igi) {
			ret = -ENOMEM;
			break;
		}

		le_init(&igi->le);

		ipcon_c_lock(iph);
		ret = ipcon_get_group(iph, peer_name, group_name, &groupid);
		if (ret < 0) {
			free(igi);
			break;
		}
		ipcon_c_unlock(iph);

		/* Use r_chan to receive multicast message */
		ipcon_r_lock(iph);
		igi->groupid = groupid;
		strcpy(igi->group_name, group_name);
		strcpy(igi->peer_name, peer_name);
		le_addtail(LINK_ENTRY_HEAD(iph), LINK_ENTRY(igi));

		ret = nl_socket_add_memberships(iph->r_chan.sk,
					(int)groupid, 0);
		if (ret < 0) {
			le_remove(LINK_ENTRY(igi));
			free(igi);
		}
		ipcon_r_unlock(iph);

	} while (0);

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

		ipcon_c_lock(iph);
		ipconmsg_put(msg, &iph->c_chan, IPCON_GRP_UNREG,0);
		nla_put_string(msg, IPCON_ATTR_GROUP_NAME, name);
		ipconmsg_complete(&iph->c_chan, msg);

		ret = ipcon_send_rcv(&iph->c_chan, msg, NULL);
		ipcon_c_unlock(iph);

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
	struct nl_data *ipcon_data = NULL;

	if (!iph || (size <= 0) || (size > MAX_IPCONMSG_DATA_SIZE))
		return -EINVAL;

	if (!valid_name(name))
		return -EINVAL;

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_s_lock(iph);
		ipconmsg_put(msg, &iph->s_chan, IPCON_USR_MSG,0);
		nla_put_string(msg, IPCON_ATTR_PEER_NAME, name);
		ipcon_data = nl_data_alloc(buf, size);
		if (!ipcon_data) {
			ret = -ENOMEM;
			break;
		}

		nla_put_data(msg, IPCON_ATTR_DATA, ipcon_data);
		ipconmsg_complete(&iph->s_chan, msg);

		ret = ipcon_send_rcv(&iph->s_chan, msg, NULL);
		ipcon_s_unlock(iph);

	} while (0);

	if (ipcon_data)
		nl_data_free(ipcon_data);

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
	struct nl_data *ipcon_data = NULL;
	struct nl_msg *msg = NULL;

	if (!iph || !buf)
		return -EINVAL;

	if (!valid_name(name))
		return -EINVAL;

	do {

		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipcon_s_lock(iph);
		ipconmsg_put(msg, &iph->s_chan, IPCON_MULTICAST_MSG,0);
		nla_put_string(msg, IPCON_ATTR_GROUP_NAME, name);
		if (sync)
			nla_put_u32(msg, IPCON_ATTR_FLAG,
					IPCON_FLG_MULTICAST_SYNC);

		ipcon_data = nl_data_alloc(buf, size);
		if (!ipcon_data) {
			ret = -ENOMEM;
			break;
		}
		nla_put_data(msg, IPCON_ATTR_DATA, ipcon_data);
		ipconmsg_complete(&iph->s_chan, msg);

		ret = ipcon_send_rcv(&iph->s_chan, msg, NULL);
		ipcon_s_unlock(iph);

	} while (0);

	if (ipcon_data)
		nl_data_free(ipcon_data);

	return ret;
}

/*
 * ipcon_leave_group
 *
 * Unsuscribe a multicast group.
 *
 */
int ipcon_leave_group(IPCON_HANDLER handler, char *peer_name, char *group_name)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	struct ipcon_group_info *igi = NULL;
	int ret = 0;
	int groupid = -1;

	if (!iph || !peer_name || !group_name)
		return -EINVAL;

	ipcon_r_lock(iph);
	for (igi = le_next(LINK_ENTRY(iph)); igi;
			igi = le_next(LINK_ENTRY(igi))) {
		if (!strcmp(igi->group_name, group_name) &&
			!strcmp(igi->peer_name, peer_name))
			break;

	}

	if (igi) {
		ret = nl_socket_drop_membership(iph->r_chan.sk,
				(int)igi->groupid);
		if (!ret)
			le_remove(LINK_ENTRY(igi));
	}
	ipcon_r_unlock(iph);

	return ret;
}

/*
 * ipcon_getfd
 *
 * Return the socket fd for user to do select(), poll() and etc.
 */

int ipcon_get_read_fd(IPCON_HANDLER handler)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);

	if (iph)
		return nl_socket_get_fd(iph->r_chan.sk);

	return -EBADF;
}

int ipcon_get_write_fd(IPCON_HANDLER handler)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);

	if (iph)
		return nl_socket_get_fd(iph->s_chan.sk);

	return -EBADF;
}

int ipcon_get_ctrl_fd(IPCON_HANDLER handler)
{
	struct ipcon_peer_handler *iph = handler_to_iph(handler);

	if (iph)
		return nl_socket_get_fd(iph->c_chan.sk);

	return -EBADF;
}


int ipcon_rcv_timeout(IPCON_HANDLER handler, struct ipcon_msg *im,
		struct timeval *timeout)
{
	int ret = 0;
	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	struct nl_msg *msg = NULL;

	if (!iph || !im)
		return -EINVAL;

	ipcon_r_lock(iph);
	do {
		int fd = nl_socket_get_fd(iph->r_chan.sk);
		struct nlmsghdr *nlh = NULL;
		int len;
		fd_set rfds;


		if (timeout) {
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);

redo:
			ret = select(fd + 1, &rfds, NULL, NULL, timeout);
			if (ret == 0) {
				ret = -ETIMEDOUT;
			} else if (ret < 0) {
				if (errno == EINTR)
					goto redo;

				ret = -errno;
			}

			if (ret < 0)
				break;

		}

		ret = ipcon_recvmsg(&iph->r_chan, &msg);
		if (ret < 0)
			break;

		struct nlattr *peer_name_attr;
		struct nlattr *group_name_attr;

		switch (ipconmsg_type(msg)) {
		case IPCON_USR_MSG:
			im->type = LIBIPCON_NORMAL_MSG;
			struct nlattr *peer_name_attr =
				ipcon_find_attr(msg, IPCON_ATTR_PEER_NAME);

			if (!peer_name_attr) {
				ret = -EREMOTEIO;
				break;
			}

			strcpy(im->peer, nla_get_string(peer_name_attr));
			break;
		case IPCON_MULTICAST_MSG:
			peer_name_attr = ipcon_find_attr(msg,
					IPCON_ATTR_PEER_NAME);

			group_name_attr = ipcon_find_attr(msg,
					IPCON_ATTR_GROUP_NAME);

			if (!peer_name_attr || !group_name_attr) {
				ret = -EREMOTEIO;
				break;
			}

			if (!strcmp(IPCON_KERNEL_GROUP_NAME,
					nla_get_string(group_name_attr)))
				im->type = LIBIPCON_KEVENT_MSG;
			else
				im->type = LIBIPCON_GROUP_MSG;

			strcpy(im->peer, nla_get_string(peer_name_attr));
			strcpy(im->group, nla_get_string(group_name_attr));
			break;
		default:
			im->type = LIBIPCON_INVALID_MSG;
			break;

		}

		if (im->type == LIBIPCON_INVALID_MSG) {
			ret = -EREMOTEIO;
			break;
		}

		struct nlattr *data_attr = ipcon_find_attr(msg,
					IPCON_ATTR_DATA);

		if (!data_attr) {
			ret = -EREMOTEIO;
			break;
		}

		im->len = (__u32) nla_len(data_attr);
		memcpy((void *)im->buf, nla_data(data_attr), (size_t)im->len);

	} while (0);
	ipcon_r_unlock(iph);
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

