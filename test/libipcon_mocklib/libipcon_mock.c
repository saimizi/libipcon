#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <assert.h>
#include <string.h>

// should be last
#include <cmocka.h>
#include <netlink/msg.h>
#include <unistd.h>

#include "libipcon_priv.h"

extern int __real_ipcon_chan_init(struct ipcon_peer_handler *iph);
int __attribute__((weak)) __wrap_ipcon_chan_init(struct ipcon_peer_handler *iph)
{
	return __real_ipcon_chan_init(iph);
}
