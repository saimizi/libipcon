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
#include <netlink/errno.h>
#include <netlink/attr.h>
#include <pthread.h>
#include <time.h>

#include "libipcon_dbg.h"
#include "libipcon_priv.h"

void __attribute__ ((constructor)) libipcon_init(void)
{
	libipcon_dbg_init();
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
	int ret = -1;
	size_t name_len = 0;

	do {
		int i;
		int family;
		struct nl_msg *msg = NULL;


		if (!valid_peer_name(name))
			break;

		ipcon_dbg("Peer name: %s\n", name);

		iph = malloc(sizeof(*iph));
		if (!iph)
			break;

		if (peer_name) {
			iph->name = strdup(peer_name);
		} else {
			iph->flags |= IPH_FLG_ANON_PEER;
			iph->name = auto_peer_name();
		}

		if (ipcon_chan_init(iph)
			break;

		ipcon_dbg("Ctrl port: %lu.\n",
				(unsigned long)iph->ctrl_chan.port);
		ipcon_dbg("Comm port: %lu.\n",
				(unsigned long)iph->chan.port);

		lh_init(&iph->grp);

		ret = 0;

	} while (0);

	if (ret < 0){

		if (iph) {
			/* NULL is ok for ipcon_chan_destory() */
			ipcon_chan_destory(&iph->chan);
			ipcon_chan_destory(&iph->ctrl_chan);
			free(iph);
			iph = NULL

			if (name)
				free(name);
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

		ipconmsg_put(msg, &iph->ctrl_chan, IPCON_TYPE_CTL, 0,
				IPCON_GRP_REG);
		nla_put_string(msg, IPCON_ATTR_GROUP_NAME, name);
		nl_complete_msg(&iph->ctrl_chan, msg);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv(&iph->ctrl_chan, msg, NULL);
		ipcon_ctrl_unlock(iph);
	} while (0);

	nlmsg_free(msg);


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

		ipconmsg_put(msg, &iph->ctrl_chan, IPCON_TYPE_CTL,
				0, IPCON_PEER_RESLOVE);
		nla_put_string(msg, IPCON_ATTR_PEER_NAME, name);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv(&iph->ctrl_chan, msg, NULL);
		ipcon_ctrl_unlock(iph);

	} while (0);
	nlmsg_free(msg);

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

		ipconmsg_put(msg, &iph->ctrl_chan, IPCON_TYPE_CTL,
				0, IPCON_GRP_RESLOVE);
		nla_put_string(msg, IPCON_ATTR_PEER_NAME, peer_name);
		nla_put_string(msg, IPCON_ATTR_GROUP_NAME, group_name);
		nl_complete_msg(&iph->ctrl_chan, msg);

		ret = ipcon_send_rcv(&iph->ctrl_chan, msg, &rmsg);
		if (!ret) {
			struct nlattr  *group_attr;

			assert(msg);

			group_attr = ipcon_find_attr(msg, IPCON_ATTR_GROUP);
			assert(group_attr);

			if (groupid)
				*groupid = nla_get_u32(group_attr);

		}
	} while (0);

	nlmsg_free(msg);
	nlmsg_free(rmsg);

	return ret;
}

int is_group_present(IPCON_HANDLER handler, char *peer_name, char *group_name)
{
	int ret = 0;
	struct ipcon_peer_handler *iph = handler_to_iph(handler);

	if (!iph || !valid_name(peer_name) || !valid_name(group_name))
		return -EINVAL;

	ipcon_ctrl_lock(iph);
	ret = ipcon_get_group(iph, peer_name, group_name, NULL);
	ipcon_ctrl_unlock(iph);

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

	if (!valid_peer_name(peer_name))
		return -EINVAL;

	if (!valid_peer_name(group_name))
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

		ret = ipcon_get_group(iph, peer_name, group_name, &groupid);
		if (ret < 0) {
			free(igi);
			break;
		}

		igi->groupid = groupid;
		strcpy(igi->group_name, group_name);
		strcpy(igi->peer_name, peer_name);
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

		ipconmsg_put(msg, &iph->ctrl_chan, IPCON_TYPE_CTL,
				0, IPCON_GRP_UNREG);
		nla_put_string(msg, IPCON_ATTR_GRP_NAME, name);
		nl_complete_msg(&iph->ctrl_chan, msg);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv(&iph->ctrl_chan, msg, NULL);
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
	struct nl_data *ipcon_data = NULL;

	if (!iph || (size <= 0) || (size > IPCON_MAX_MSG_LEN))
		return -EINVAL;

	if (!valid_name(name))
		return -EINVAL;

	do {
		msg = nlmsg_alloc();
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		ipconmsg_put(msg, &iph->chan, IPCON_TYPE_MSG,
				0, IPCON_USR_MSG);

		nla_put_string(msg, IPCON_ATTR_PEER_NAME, name);
		ipcon_data = nl_data_alloc(buf, size);
		if (!ipcon_data) {
			ret = -ENOMEM;
			break;
		}

		nla_put_data(msg, IPCON_ATTR_DATA, ipcon_data);
		nl_complete_msg(&iph->chan, msg);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv(&iph->chan, msg, NULL);
		ipcon_ctrl_unlock(iph);

	} while (0);

	nlmsg_free(msg);

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

		ipconmsg_put(msg, &iph->chan, IPCON_TYPE_MSG,
				0, IPCON_MULTICAST_MSG);

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
		nl_complete_msg(&iph->chan, msg);

		ipcon_ctrl_lock(iph);
		ret = ipcon_send_rcv_msg(&iph->chan, 0, msg, NULL);
		ipcon_ctrl_unlock(iph);

	} while (0);

	nlmsg_free(msg);

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

	if (!iph || !grpname)
		return -EINVAL;

	ipcon_ctrl_lock(iph);
	for (igi = le_next(LINK_ENTRY(iph)); igi;
			igi = le_next(LINK_ENTRY(igi))) {
		if (!strcmp(igi->group_name, group_name) &&
			!strcmp(igi->peer_name, peer_name)) {
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

	ipcon_com_lock(iph);
	do {
		int fd = nl_socket_get_fd(iph->chan.sk);
		struct nlmsghdr *nlh = NULL;
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

		ret = ipcon_rcv_msg(&iph->chan, &msg);
		ipcon_com_unlock(iph);

		if (ret < 0)
			break;


		im->type = ipconmsg_cmd(msg);
		if (im->type == IPCON_USR_MSG) {
			struct nlattr *peer_name_attr =
				ipcon_find_attr(msg, IPCON_ATTR_PEER_NAME);

			if (!peer_name_attr) {
				ret = -EREMOTEIO;
				break;
			}

			strcpy(im->group, nla_get_string(peer_name_attr));

		} else if (im->type == IPCON_MULTICAST_MSG) {
			struct nlattr *peer_name_attr =
				ipcon_find_attr(msg, IPCON_ATTR_PEER_NAME);

			struct nlattr *group_name_attr =
				ipcon_find_attr(msg, IPCON_ATTR_GROUP_NAME);

			if (!peer_name_attr || !group_name_attr) {
				ret = -EREMOTEIO;
				break;
			}

			strcpy(im->peer, nla_get_string(peer_name_attr));
			strcpy(im->group, nla_get_string(group_name_attr));
		} else {
			ret = -EREMOTEIO;
		}

		{
			struct nlattr *data_attr =
				ipcon_find_attr(msg, IPCON_ATTR_DATA)

			if (!data_attr) {
				ret = -EREMOTEIO;
				break;
			}

			im->len = (__u32) nla_len(data_attr);
			memcpy((void *)im->buf, nla_data(data_attr),
				(size_t)im->len);
		}

	} while (0);
	ipcon_com_unlock(iph);
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
