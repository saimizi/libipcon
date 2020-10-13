#ifndef __LIBIPCON_H__
#define __LIBIPCON_H__

#include <string.h>
#include "ipcon.h"


#define IPCON_HANDLER	void *

#define IPCON_MAX_USR_GROUP	5

#define IPCON_NORMAL_MSG	IPCON_MSG_UNICAST
#define IPCON_GROUP_MSG		IPCON_MSG_MULTICAST


struct ipcon_msg {
        __u32 type;
        char group[IPCON_MAX_NAME_LEN];
        char peer[IPCON_MAX_NAME_LEN];
        char buf[IPCON_MAX_MSG_LEN];
        __u32 len;
};

static inline ipconmsg_cmd(struct nl_msg *msg)
{
	(struct ipcon_msghdr *)nlmsg_data(nlmsg_hdr(msg))->cmd;
}

static inline ipconmsg_version(struct nl_msg *msg)
{
	(struct ipcon_msghdr *)nlmsg_data(nlmsg_hdr(msg))->version;
}



IPCON_HANDLER ipcon_create_handler(char *peer_name, enum peer_type type);
void ipcon_free_handler(IPCON_HANDLER handler);
int is_peer_present(IPCON_HANDLER handler, char *name);
int is_group_present(IPCON_HANDLER handler, char *peer_name, char *group_name);
int ipcon_rcv(IPCON_HANDLER handler, struct ipcon_msg *im);
int ipcon_send_unicast(IPCON_HANDLER handler, char *name,
				void *buf, size_t size);
int ipcon_register_group(IPCON_HANDLER handler, char *name);
int ipcon_unregister_group(IPCON_HANDLER handler, char *name);
int ipcon_join_group(IPCON_HANDLER handler, char *srvname, char *grpname);
int ipcon_leave_group(IPCON_HANDLER handler, char *srvname, char *grpname);
__u32 ipcon_get_selfport(IPCON_HANDLER handler);
int ipcon_getfd(IPCON_HANDLER handler);
int ipcon_find_group(IPCON_HANDLER handler, char *name, __u32 *groupid);
int ipcon_send_multicast(IPCON_HANDLER handler, char *name, void *buf,
			size_t size, int sync);
int ipcon_rcv_timeout(IPCON_HANDLER handler, struct ipcon_msg *im,
		struct timeval *timeout);

int ipcon_rcv_nonblock(IPCON_HANDLER handler, struct ipcon_msg *im);
const char *ipcon_selfname(IPCON_HANDLER handler);
#endif
