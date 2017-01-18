#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <fcntl.h>

#include "libipcon.h"
#include "libipcon_internal.h"

/*
 * ipcon_create_handler
 * Create and return a ipcon handler with an internal structure ipcon_mng_info.
 */

IPCON_HANDLER ipcon_create_handler(void)
{
}

/*
 * ipcon_free_handler
 * Free an ipcon handler created by ipcon_create_handler().
 */
int ipcon_free_handler(IPCON_HANDLER handler)
{
}

/*
 * ipcon_register_service
 *
 * Register a service point. A service must have a name and may or may not have
 * a group. The following information of a service point can be resloved by
 * using ipcon_find_service() with the name of the service.
 *
 * - Port
 * - Group number
 */

int ipcon_register_service(IPCON_HANDLER handler, char *name,
				unsigned int group)
{
}


/*
 * ipcon_unregister_service
 *
 * Remove service registration. this make service point be an anonymous one.
 *
 */

int ipcon_unregister_service(IPCON_HANDLER handler)
{
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
