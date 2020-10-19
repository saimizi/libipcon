#ifndef __LIBIPCON_H__
#define __LIBIPCON_H__

#include <string.h>

#define IPCON_HANDLER	void *

enum libipcon_msg_type {
	LIBIPCON_NORMAL_MSG,
	LIBIPCON_GROUP_MSG,
	LIBIPCON_KEVENT_MSG,
	LIBIPCON_INVALID_MSG,
};


#define LIBIPCON_KERNEL_NAME		"ipcon"
#define LIBIPCON_KERNEL_GROUP_NAME	"ipcon_kevent"
#define LIBIPCON_MAX_PAYLOAD_LEN	2048
#define LIBIPCON_MAX_NAME_LEN		32
#define LIBIPCON_MAX_USR_GROUP		5

#define LIBIPCON_FLG_DISABLE_KEVENT_FILTER	(1UL << 0)


enum libipcon_kevent_type {
	LIBIPCON_EVENT_PEER_ADD,
	LIBIPCON_EVENT_PEER_REMOVE,
	LIBIPCON_EVENT_GRP_ADD,
	LIBIPCON_EVENT_GRP_REMOVE,
};

struct libipcon_kevent{
	enum libipcon_kevent_type type;
	union {
		struct {
			char name[LIBIPCON_MAX_NAME_LEN];
			char peer_name[LIBIPCON_MAX_NAME_LEN];
		} group;
		struct {
			char name[LIBIPCON_MAX_NAME_LEN];
		} peer;
	};
};

struct ipcon_msg {
	enum libipcon_msg_type type;
	char group[LIBIPCON_MAX_NAME_LEN];
	char peer[LIBIPCON_MAX_NAME_LEN];
	__u32 len;
	union {
		char buf[LIBIPCON_MAX_PAYLOAD_LEN];
		struct libipcon_kevent kevent;
	};
};

IPCON_HANDLER ipcon_create_handler(char *peer_name, unsigned long flags);
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

int ipcon_get_read_fd(IPCON_HANDLER handler);
int ipcon_get_write_fd(IPCON_HANDLER handler);

int ipcon_find_group(IPCON_HANDLER handler, char *name, __u32 *groupid);
int ipcon_send_multicast(IPCON_HANDLER handler, char *name, void *buf,
			size_t size, int sync);
int ipcon_rcv_timeout(IPCON_HANDLER handler, struct ipcon_msg *im,
		struct timeval *timeout);

int ipcon_rcv_nonblock(IPCON_HANDLER handler, struct ipcon_msg *im);
const char *ipcon_selfname(IPCON_HANDLER handler);
#endif
