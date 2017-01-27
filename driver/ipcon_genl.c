/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <net/sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <asm/bitops.h>

#include "ipcon.h"
#include "ipcon_genl.h"
#include "ipcon_tree.h"
#include "ipcon_dbg.h"

/* Reference
 * - inclue/net/netlink.h
 */

#define UNUSED_GROUP_NAME	"ipconG"
static struct genl_multicast_group ipcon_mcgroups[IPCON_MAX_GROUP_NUM];
static struct ipcon_tree_root cp_srvtree_root;
static struct ipcon_tree_root cp_grptree_root;

static struct genl_family ipcon_fam = {
	.id = GENL_ID_GENERATE,
	.name = IPCON_GENL_NAME,
	.hdrsize = IPCON_HDR_SIZE,
	.version = 1,
	.maxattr = IPCON_ATTR_MAX,
	.parallel_ops = false,	/* Consider to set it to true...*/
};

static const struct nla_policy ipcon_policy[NUM_IPCON_ATTR] = {
	[IPCON_ATTR_MSG_TYPE] = {.type = NLA_U32},
	[IPCON_ATTR_PORT] = {.type = NLA_U32},
	[IPCON_ATTR_SRV_NAME] = {.type = NLA_NUL_STRING,
				.len = IPCON_MAX_SRV_NAME_LEN - 1},
	[IPCON_ATTR_GROUP] = {.type = NLA_U32},
	[IPCON_ATTR_GRP_NAME] = {.type = NLA_NUL_STRING,
				.len = IPCON_MAX_GRP_NAME_LEN - 1 },
	[IPCON_ATTR_DATA] = {.type = NLA_BINARY, .len = IPCON_MAX_MSG_LEN},
};

static void ipcon_send_kevent(struct ipcon_kevent *ik, gfp_t flags)
{
	int ret = 0;
	struct sk_buff *msg;
	void *hdr;

	if (!ik)
		return;

	do {
		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg)
			break;

		hdr = genlmsg_put(msg, 0, 0, &ipcon_fam, 0, IPCON_MULICAST_MSG);
		if (!hdr)
			break;

		ret = nla_put_u32(msg, IPCON_ATTR_MSG_TYPE,
				IPCON_MSG_MULTICAST);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			break;
		}

		ret = nla_put(msg, IPCON_ATTR_DATA, sizeof(*ik), ik);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			break;
		}

		genlmsg_end(msg, hdr);
		genlmsg_multicast(&ipcon_fam, msg, 0,
					IPCON_KERNEL_GROUP, flags);

	} while (0);

	nlmsg_free(msg);
}

/*
 * This function is called from another context.
 */
static int ipcon_netlink_notify(struct notifier_block *nb,
				  unsigned long state,
				  void *_notify)
{
	return 0;
}

static int ipcon_srv_reg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_SRV_NAME_LEN];
	__u32 port;
	__u32 msg_type;
	struct ipcon_tree_node *nd = NULL;

	ipcon_dbg("ipcon_srv_reg() enter.\n");

	ipcon_wrlock_tree(&cp_srvtree_root);
	do {

		if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
			!info->attrs[IPCON_ATTR_PORT] ||
			!info->attrs[IPCON_ATTR_SRV_NAME]) {
			ret = -EINVAL;
			break;
		}

		msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
		if (msg_type != IPCON_MSG_UNICAST) {
			ret = -EINVAL;
			break;
		}

		port = nla_get_u32(info->attrs[IPCON_ATTR_PORT]);
		nla_strlcpy(name, info->attrs[IPCON_ATTR_SRV_NAME],
				IPCON_MAX_SRV_NAME_LEN);


		nd = cp_alloc_srv_node(port, info->snd_portid, name);
		if (!nd) {
			ret = -ENOMEM;
			break;
		}

		ret = cp_insert(&cp_srvtree_root, nd);

	} while (0);

	if (ret < 0) {
		cp_free_node(nd);
	} else {
		struct ipcon_kevent ik;

		ik.type = IPCON_EVENT_SRV_ADD;
		strcpy(ik.srv.name, name);
		ik.srv.portid = nd->port;

		ipcon_send_kevent(&ik, GFP_ATOMIC);
	}

	ipcon_wrunlock_tree(&cp_srvtree_root);

	ipcon_dbg("ipcon_srv_reg() exit (%d).\n", ret);
	return ret;
}

static int ipcon_srv_unreg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_SRV_NAME_LEN];
	__u32 ctrl_port;
	__u32 msg_type;
	struct ipcon_tree_node *nd = NULL;

	ipcon_dbg("ipcon_srv_unreg() enter.\n");
	do {
		struct ipcon_kevent ik;

		if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
			!info->attrs[IPCON_ATTR_SRV_NAME]) {
			ret = -EINVAL;
			break;
		}

		msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
		if (msg_type != IPCON_MSG_UNICAST) {
			ret = -EINVAL;
			break;
		}

		ctrl_port = info->snd_portid;
		nla_strlcpy(name, info->attrs[IPCON_ATTR_SRV_NAME],
				IPCON_MAX_SRV_NAME_LEN);

		ipcon_wrlock_tree(&cp_srvtree_root);
		nd = cp_lookup(&cp_srvtree_root, name);
		if (!nd) {
			ret = -ENOENT;
			ipcon_wrunlock_tree(&cp_srvtree_root);
			break;
		}

		/* Only the port who registered service can unregister it */
		if (nd->ctrl_port != ctrl_port) {
			ret = -EPERM;
			ipcon_wrunlock_tree(&cp_srvtree_root);
			break;
		}

		cp_detach_node(&cp_srvtree_root, nd);

		ik.type = IPCON_EVENT_SRV_REMOVE;
		strcpy(ik.srv.name, name);
		ik.srv.portid = nd->port;
		ipcon_send_kevent(&ik, GFP_ATOMIC);

		cp_free_node(nd);

		ipcon_wrunlock_tree(&cp_srvtree_root);

	} while (0);

	ipcon_dbg("ipcon_srv_unreg() exit (%d).\n", ret);
	return ret;
}

static int ipcon_srv_reslove(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_SRV_NAME_LEN];
	__u32 port;
	__u32 msg_type;
	struct ipcon_tree_node *nd = NULL;
	void *hdr;

	ipcon_info("ipcon_srv_reslove() enter.\n");
	do {
		struct sk_buff *msg;

		if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
			!info->attrs[IPCON_ATTR_SRV_NAME]) {
			ret = -EINVAL;
			break;
		}

		msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
		if (msg_type != IPCON_MSG_UNICAST) {
			ret = -EINVAL;
			break;
		}

		port = info->snd_portid;
		nla_strlcpy(name, info->attrs[IPCON_ATTR_SRV_NAME],
				IPCON_MAX_SRV_NAME_LEN);

		ipcon_rdlock_tree(&cp_srvtree_root);
		nd = cp_lookup(&cp_srvtree_root, name);
		ipcon_rdunlock_tree(&cp_srvtree_root);

		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		hdr = genlmsg_put(msg, 0, 0, &ipcon_fam, 0, IPCON_SRV_RESLOVE);

		if (!hdr) {
			nlmsg_free(msg);
			ret = -ENOBUFS;
			break;
		}

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		if (nd) {
			nla_put_u32(msg, IPCON_ATTR_PORT, nd->port);
			ipcon_dbg("%s: found %s@%lu.\n",
					__func__,
					name,
					(unsigned long)nd->port);
		} else {
			ipcon_dbg("%s: service %s not found.\n",
					__func__,
					name);
		}

		genlmsg_end(msg, hdr);

		ret = genlmsg_reply(msg, info);

	} while (0);

	return ret;
}

static int ipcon_grp_reg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_GRP_NAME_LEN];
	__u32 msg_type;
	struct ipcon_tree_node *nd = NULL;

	ipcon_dbg("ipcon_srv_reg() enter.\n");

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_GRP_NAME])
		return -EINVAL;

	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_UNICAST)
		return -EINVAL;

	nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
		IPCON_MAX_GRP_NAME_LEN);

	ipcon_wrlock_tree(&cp_grptree_root);
	do {
		int id = 0;
		struct ipcon_kevent ik;

		if (cp_grptree_root.count > IPCON_MAX_GROUP_NUM - 1) {
			ret = -ENOBUFS;
			break;
		}

		nd = cp_lookup(&cp_grptree_root, name);
		if (nd) {
			nd = NULL;
			ret = -EEXIST;
			break;
		}

		id = find_first_zero_bit(cp_grptree_root.group_bitmap,
					IPCON_MAX_GROUP_NUM);

		if (id >= IPCON_MAX_GROUP_NUM) {
			ret = -ENOBUFS;
			break;
		}

		nd = cp_alloc_grp_node(info->snd_portid, name, (__u32)id);
		if (!nd) {
			ret = -ENOMEM;
			break;
		}

		ret = cp_insert(&cp_grptree_root, nd);
		if (ret < 0) {
			cp_free_node(nd);
			break;
		}

		set_bit(id, cp_grptree_root.group_bitmap);

		ik.type = IPCON_EVENT_GRP_ADD;
		strcpy(ik.grp.name, name);
		ik.grp.groupid = nd->group + ipcon_fam.mcgrp_offset;

		ipcon_send_kevent(&ik, GFP_ATOMIC);

	} while (0);

	ipcon_wrunlock_tree(&cp_grptree_root);
	ipcon_dbg("ipcon_grp_reg() exit (%d).\n", ret);

	return ret;
}

static int ipcon_grp_unreg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_GRP_NAME_LEN];
	__u32 ctrl_port;
	__u32 msg_type;
	struct ipcon_tree_node *nd = NULL;

	ipcon_dbg("ipcon_grp_unreg() enter.\n");
	do {
		struct ipcon_kevent ik;

		if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
			!info->attrs[IPCON_ATTR_GRP_NAME]) {
			ret = -EINVAL;
			break;
		}

		msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
		if (msg_type != IPCON_MSG_UNICAST) {
			ret = -EINVAL;
			break;
		}

		ctrl_port = info->snd_portid;
		nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
				IPCON_MAX_GRP_NAME_LEN);

		ipcon_wrlock_tree(&cp_srvtree_root);

		nd = cp_lookup(&cp_grptree_root, name);
		if (!nd) {
			ret = -ENOENT;
			ipcon_wrunlock_tree(&cp_grptree_root);
			break;
		}

		/* Only the port who registered group can unregister it */
		if (nd->ctrl_port != ctrl_port) {
			ret = -EPERM;
			ipcon_wrunlock_tree(&cp_grptree_root);
			break;
		}

		ret = cp_detach_node(&cp_grptree_root, nd);

		ik.type = IPCON_EVENT_GRP_REMOVE;
		strcpy(ik.grp.name, name);
		ik.grp.groupid = nd->group + ipcon_fam.mcgrp_offset;
		ipcon_send_kevent(&ik, GFP_ATOMIC);

		cp_free_node(nd);

		ipcon_wrunlock_tree(&cp_srvtree_root);

	} while (0);

	ipcon_dbg("ipcon_grp_unreg() exit (%d).\n", ret);
	return ret;
}

static int ipcon_grp_reslove(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_GRP_NAME_LEN];
	__u32 ctrl_port;
	__u32 msg_type;
	__u32 tgt_group;
	int found = 0;
	struct ipcon_tree_node *nd = NULL;
	void *hdr;

	ipcon_info("ipcon_grp_reslove() enter.\n");
	do {
		struct sk_buff *msg;

		if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
			!info->attrs[IPCON_ATTR_GRP_NAME]) {
			ret = -EINVAL;
			break;
		}

		msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
		if (msg_type != IPCON_MSG_UNICAST) {
			ret = -EINVAL;
			break;
		}

		ctrl_port = info->snd_portid;
		nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
				IPCON_MAX_GRP_NAME_LEN);

		if (!strcmp(IPCON_KERNEL_GROUP_NAME, name)) {
			tgt_group = IPCON_KERNEL_GROUP +
					ipcon_fam.mcgrp_offset;
			found = 1;
		} else {
			ipcon_rdlock_tree(&cp_grptree_root);
			nd = cp_lookup(&cp_grptree_root, name);
			ipcon_rdunlock_tree(&cp_grptree_root);

			if (nd) {
				tgt_group = nd->group + ipcon_fam.mcgrp_offset;
				found = 1;
			}
		}

		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		hdr = genlmsg_put(msg, 0, 0, &ipcon_fam, 0, IPCON_GRP_RESLOVE);
		if (!hdr) {
			nlmsg_free(msg);
			ret = -ENOBUFS;
			break;
		}

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		if (found) {
			nla_put_u32(msg, IPCON_ATTR_GROUP, tgt_group);
			ipcon_dbg("%s: found group %s@%lu.\n",
					__func__,
					name,
					(unsigned long)tgt_group);
		} else {
			ipcon_dbg("%s: group %s not found.\n",
					__func__,
					name);
		}

		genlmsg_end(msg, hdr);

		ret = genlmsg_reply(msg, info);

	} while (0);
	ipcon_dbg("ipcon_grp_reslove() exit(%d).\n", ret);

	return ret;
}

static const struct genl_ops ipcon_ops[] = {
	{
		.cmd = IPCON_SRV_REG,
		.doit = ipcon_srv_reg,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
	{
		.cmd = IPCON_SRV_UNREG,
		.doit = ipcon_srv_unreg,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
	{
		.cmd = IPCON_SRV_RESLOVE,
		.doit = ipcon_srv_reslove,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
	{
		.cmd = IPCON_GRP_REG,
		.doit = ipcon_grp_reg,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
	{
		.cmd = IPCON_GRP_UNREG,
		.doit = ipcon_grp_unreg,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
	{
		.cmd = IPCON_GRP_RESLOVE,
		.doit = ipcon_grp_reslove,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	}
};


static struct notifier_block ipcon_netlink_notifier = {
	.notifier_call = ipcon_netlink_notify,
};

int ipcon_genl_init(void)
{
	int ret = 0;
	int i = 0;

	ipcon_init_tree(&cp_srvtree_root);
	ipcon_init_tree(&cp_grptree_root);

	for (i = 0; i < IPCON_MAX_GROUP_NUM; i++) {
		if (i)
			sprintf(ipcon_mcgroups[i].name, "%s%d",
					UNUSED_GROUP_NAME, i);
		else
			strcpy(ipcon_mcgroups[i].name, IPCON_KERNEL_GROUP_NAME);
	}

	ret = genl_register_family_with_ops_groups(&ipcon_fam, ipcon_ops,
						ipcon_mcgroups);
	if (ret)
		return ret;

	ret = netlink_register_notifier(&ipcon_netlink_notifier);
	if (ret)
		genl_unregister_family(&ipcon_fam);

	return ret;
}

void ipcon_genl_exit(void)
{

	netlink_unregister_notifier(&ipcon_netlink_notifier);
	genl_unregister_family(&ipcon_fam);
}

