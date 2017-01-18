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

#define ipcon_dbg(fmt, ...)	printf("[ipcon] Debug "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...)	printf("[ipcon] Info "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...)	printf("[ipcon] Error "fmt, ##__VA_ARGS__)

int ipcon_family;


static int rcv_msg(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);

	ipcon_info("%s - %d\n", __func__, __LINE__);

	if (nlh->nlmsg_type != ipcon_family)
		return NL_STOP;


	return NL_OK;
}

int main(int argc, char *argv[])
{

	int ret = 0;
	struct nl_sock *sk = NULL;
	struct nl_msg *msg = NULL;
	void *hdr = NULL;

	do {
		sk = nl_socket_alloc();
		if (!sk) {
			ipcon_err("sk alloc failed.\n");
			ret = 1;
			break;
		}
		ipcon_dbg("local port %u\n", nl_socket_get_local_port(sk));

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

		ret = nl_socket_modify_cb(sk,
					NL_CB_VALID,
					NL_CB_CUSTOM,
					rcv_msg,
					NULL);
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

		hdr = genlmsg_put(msg, 0, 0, ipcon_family,
				IPCON_HDR_SIZE, 0, IPCON_SRV_REG, 1);
		if (!hdr) {
			ipcon_err("failed to setup msg.\n");
			ret = 1;
			break;
		}

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_u32(msg, IPCON_ATTR_SRV_PORT,
				nl_socket_get_local_port(sk));
		nla_put_string(msg, IPCON_ATTR_SRV_NAME, "ipcon_test");
		nla_put_u32(msg, IPCON_ATTR_SRV_GROUP, IPCON_AUTO_GROUP);


		ret = nl_send_auto_complete(sk, msg);
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
