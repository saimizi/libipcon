#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "ipcon.h"
#include "libipcon.h"
#include "ipcon_logger.h"

#define ipcon_info(fmt, ...) \
	fprintf(stderr, fmt, ##__VA_ARGS__)

IPCON_HANDLER kevent_h;

static void ipcon_kevent(struct ipcon_msg *im)
{
	struct libipcon_kevent *ik;

	if (!im)
		return;

	ik = &im->kevent;

	struct timeval tv;

	gettimeofday(&tv, NULL);

	switch (ik->type) {
	case LIBIPCON_EVENT_GRP_ADD:
		ipcon_info("%15lu.%06lu\t%-32s %-32s %-32s\n",
				tv.tv_sec, tv.tv_usec,
				"LIBIPCON_EVENT_GRP_ADD",
				ik->group.peer_name,
				ik->group.name);
		ipcon_logger(kevent_h, "Group %s.%s added.",
				ik->group.peer_name,
				ik->group.name);
		break;

	case LIBIPCON_EVENT_GRP_REMOVE:
		ipcon_info("%15lu.%06lu\t%-32s %-32s %-32s\n",
				tv.tv_sec, tv.tv_usec,
				"LIBIPCON_EVENT_GRP_REMOVE",
				ik->group.peer_name,
				ik->group.name);
		ipcon_logger(kevent_h, "Group %s.%s removed.",
				ik->group.peer_name,
				ik->group.name);
		break;

	case LIBIPCON_EVENT_PEER_ADD:
		ipcon_info("%15lu.%06lu\t%-32s %-32s\n",
				tv.tv_sec, tv.tv_usec,
				"LIBIPCON_EVENT_PEER_ADD",
				ik->peer.name);
		ipcon_logger(kevent_h, "Peer %s added.",
				ik->peer.name);
		break;

	case LIBIPCON_EVENT_PEER_REMOVE:
		ipcon_info("%15lu.%06lu\t%-32s %-32s\n",
				tv.tv_sec, tv.tv_usec,
				"LIBIPCON_EVENT_PEER_REMOVE",
				ik->peer.name);
		ipcon_logger(kevent_h, "Peer %s removed.",
				ik->peer.name);
		break;
	default:
		break;
	}
}



int main(int argc, char *argv[])
{
	int ret = 0;
	unsigned int should_quit = 0;

	do {
		/* Create server handler */
		kevent_h = ipcon_create_handler("ipcon-kevent",
				LIBIPCON_FLG_DISABLE_KEVENT_FILTER);
		assert(kevent_h);
			
		ret = ipcon_join_group(kevent_h,
				LIBIPCON_KERNEL_NAME,
				LIBIPCON_KERNEL_GROUP_NAME);
		assert(ret == 0);

		while (!should_quit) {
			struct ipcon_msg im;
			fd_set rfds;
			int kfd = ipcon_get_read_fd(kevent_h);
			int nfd = kfd + 1; 

			FD_ZERO(&rfds);
			FD_SET(kfd, &rfds);

			ret = select(nfd, &rfds, NULL, NULL, NULL);
			if (ret <= 0)
				continue;

			if (FD_ISSET(kfd, &rfds)) {
				ret = ipcon_rcv_nonblock(kevent_h, &im);
				assert(ret == 0);

				if (im.type != LIBIPCON_KEVENT_MSG)
					continue;

				ipcon_kevent(&im);
			}
		}
		ipcon_leave_group(kevent_h,
				LIBIPCON_KERNEL_NAME,
				LIBIPCON_KERNEL_GROUP_NAME);

		/* Free handler */
		ipcon_free_handler(kevent_h);

	} while (0);

	exit(ret);

}
