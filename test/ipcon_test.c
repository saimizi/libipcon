#include <stdio.h>
#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "ipcon.h"

#define ipcon_dbg(fmt, ...) fprintf(stderr, "[ipcon] Debug " fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) fprintf(stderr, "[ipcon] Info " fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) fprintf(stderr, "[ipcon] Error " fmt, ##__VA_ARGS__)

int ipcon_family;

static struct nla_policy ipcon_policy[NUM_IPCON_ATTR] = {
	[IPCON_ATTR_MSG_TYPE] = { .type = NLA_U32 },
	[IPCON_ATTR_PORT] = { .type = NLA_U32 },
	[IPCON_ATTR_SRV_NAME] = { .type = NLA_NUL_STRING,
				  .maxlen = IPCON_MAX_SRV_NAME_LEN - 1 },
	[IPCON_ATTR_GROUP] = { .type = NLA_U32 },
	[IPCON_ATTR_DATA] = { .type = NLA_BINARY, .maxlen = IPCON_MAX_MSG_LEN },
};

static int srv_reg(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	__u32 port;
	__u32 group;
	char *name;
	struct nlattr *tb[NUM_IPCON_ATTR];
	int ret = NL_OK;

	ret = genlmsg_parse(nlh, IPCON_HDR_SIZE, tb, IPCON_ATTR_MAX,
			    ipcon_policy);
	if (ret)
		return NL_SKIP;

	if (!tb[IPCON_ATTR_MSG_TYPE] || !tb[IPCON_ATTR_PORT] ||
	    !tb[IPCON_ATTR_SRV_NAME] || !tb[IPCON_ATTR_SRV_GROUP])
		return NL_SKIP;

	port = nla_get_u32(tb[IPCON_ATTR_PORT]);
	name = nla_get_string(tb[IPCON_ATTR_SRV_NAME]);
	group = nla_get_u32(tb[IPCON_ATTR_SRV_GROUP]);

	ipcon_info("Name: %s, port: %lu, group: %lu\n", name,
		   (unsigned long)port, (unsigned long)group);

	return NL_OK;
}

static int rcv_msg(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *genlh = nlmsg_data(nlh);
	int ret = NL_OK;

	if (nlh->nlmsg_type != ipcon_family)
		return NL_STOP;

	switch (genlh->cmd) {
	case IPCON_SRV_REG:
		ret = srv_reg(msg, arg);
		break;
	default:
		ipcon_info("%s - %d unknown cmd: %d\n", __func__, __LINE__,
			   genlh->cmd);
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	struct nl_sock *sk = NULL;
	struct nl_msg *msg = NULL;
	void *hdr = NULL;
	__u32 local_port = 0;

	do {
		sk = nl_socket_alloc();
		if (!sk) {
			ipcon_err("sk alloc failed.\n");
			ret = 1;
			break;
		}
		local_port = nl_socket_get_local_port(sk);
		ipcon_dbg("local port %u\n", local_port);

		ret = genl_connect(sk);
		if (ret < 0) {
			ipcon_err("failed to connect (%d).\n", ret);
			ret = 1;
			break;
		}

		ipcon_family = genl_ctrl_resolve(sk, "ipcon");
		if (ipcon_family < 0) {
			ipcon_err("failed to resolve ipcon (%d).\n",
				  ipcon_family);
			ret = 1;
			break;
		}

		ipcon_info("ipcon family:%d.\n", ipcon_family);

		ret = nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
					  rcv_msg, NULL);
		if (ret < 0) {
			ipcon_err("failed setup cb (%d).\n", ret);
			ret = 1;
			break;
		}

		msg = nlmsg_alloc();
		if (!msg) {
			ipcon_err("msg alloc failed.\n");
			ret = 1;
			break;
		}

		hdr = genlmsg_put(msg, 0, 0, ipcon_family, IPCON_HDR_SIZE, 0,
				  IPCON_SRV_REG, 1);
		if (!hdr) {
			ipcon_err("failed to setup msg.\n");
			ret = 1;
			break;
		}

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_u32(msg, IPCON_ATTR_PORT, local_port);
		nla_put_string(msg, IPCON_ATTR_SRV_NAME, argv[1]);
		nla_put_u32(msg, IPCON_ATTR_SRV_GROUP, IPCON_AUTO_GROUP);

		ret = nl_send_auto(sk, msg);
		if (ret < 0) {
			ipcon_err("failed to send msg(%d).\n", ret);
			ret = 1;
			break;
		}

		nlmsg_free(msg);

		ret = nl_recvmsgs_default(sk);
		if (ret < 0) {
			ipcon_err("failed to rcv msg: %s(%d).\n",
				  strerror(-ret), -ret);
			ret = 1;
		}
	} while (0);

	nl_close(sk);

	return ret;
}
