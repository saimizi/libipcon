/*
 * This file is part of Libipcon
 * Copyright (C) 2017-2025 Seimizu Joukan
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 */

#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/uinput.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>

#include "ut.h"
#include "libipcon.h"
#include "libipcon_priv.h"

/*
 * ipcon_selfname tests
 */

static void selfname_with_name(void **state)
{
	char *peer_name = "test_peer";
	char *strdup_peer_name = "test_peer";
	char iph_mem[1024];

	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, iph_mem);

	will_return(__wrap_strdup, 1);
	expect_string(__wrap_strdup, s, peer_name);
	will_return(__wrap_strdup, strdup_peer_name);

	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	IPCON_HANDLER handler = ipcon_create_handler(peer_name, 0);
	assert_non_null(handler);

	const char *returned_name = ipcon_selfname(handler);
	assert_non_null(returned_name);
	assert_string_equal(returned_name, "test_peer");

	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, strdup_peer_name);
	will_return(__wrap__test_free, false);
	ipcon_free_handler(handler);
}

static void selfname_auto_peer(void **state)
{
	char iph_mem[1024];
	char name[IPCON_MAX_NAME_LEN];

	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, iph_mem);

	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, name);

	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	IPCON_HANDLER handler = ipcon_create_handler(NULL, 0);
	assert_non_null(handler);

	const char *returned_name = ipcon_selfname(handler);
	assert_non_null(returned_name);
	assert_true(strncmp(returned_name, "Anon-", 5) == 0);

	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, name);
	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, iph_mem);
	ipcon_free_handler(handler);
}

/*
 * ipcon_get_read_fd / ipcon_get_write_fd tests
 */

static void get_read_fd_null_handler(void **state)
{
	int fd = ipcon_get_read_fd(NULL);
	assert_int_equal(fd, -EBADF);
}

static void get_write_fd_null_handler(void **state)
{
	int fd = ipcon_get_write_fd(NULL);
	assert_int_equal(fd, -EBADF);
}

/*
 * Null handler tests for functions that properly check
 */

static void rcv_null_handler(void **state)
{
	struct ipcon_msg im;

	assert_int_equal(ipcon_rcv(NULL, &im), -EINVAL);
	assert_int_equal(ipcon_rcv_nonblock(NULL, &im), -EINVAL);
	assert_int_equal(ipcon_rcv_timeout(NULL, &im, NULL), -EINVAL);
}

static void send_null_handler(void **state)
{
	assert_int_equal(ipcon_send_unicast(NULL, "peer", "data", 4), -EINVAL);
	assert_int_equal(ipcon_send_multicast(NULL, "grp", "data", 4, 0),
			 -EINVAL);
}

static void register_null_handler(void **state)
{
	assert_int_equal(ipcon_register_group(NULL, "grp"), -EINVAL);
	assert_int_equal(ipcon_unregister_group(NULL, "grp"), -EINVAL);

	/* NULL name with NULL handler */
	assert_int_equal(ipcon_register_group(NULL, NULL), -EINVAL);
	assert_int_equal(ipcon_unregister_group(NULL, NULL), -EINVAL);
}

static void join_null_handler(void **state)
{
	assert_int_equal(ipcon_join_group(NULL, "peer", "grp"), -EINVAL);
	assert_int_equal(ipcon_leave_group(NULL, "peer", "grp"), -EINVAL);
}

static void api_invalid_names(void **state)
{
	assert_int_equal(is_peer_present(NULL, "name"), -EINVAL);
	assert_int_equal(is_group_present(NULL, "peer", "grp"), -EINVAL);
}

static void api_null_msg(void **state)
{
	/*
	 * ipcon_rcv checks !im before dereferencing handler.
	 * Passing a non-NULL handler that's not real is unsafe,
	 * but passing NULL msg is safe because im is checked first.
	 */
	assert_int_equal(ipcon_rcv((IPCON_HANDLER)0x1, NULL), -EINVAL);
}

static void send_invalid_args(void **state)
{
	/* size <= 0 should trigger early return before dereferencing handler */
	assert_int_equal(ipcon_send_unicast((IPCON_HANDLER)0x1, "peer", NULL,
					    0),
			 -EINVAL);

	assert_int_equal(ipcon_send_multicast((IPCON_HANDLER)0x1, "grp", NULL,
					      0, 0),
			 -EINVAL);
}

/*
 * Extended ipcon_create_handler tests
 */

static void create_handler_default_flags(void **state)
{
	char *peer_name = "default_test";
	char *strdup_peer_name = "default_test";
	char iph_mem[1024];

	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, iph_mem);

	will_return(__wrap_strdup, 1);
	expect_string(__wrap_strdup, s, peer_name);
	will_return(__wrap_strdup, strdup_peer_name);

	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);
	/* c_chan init needs an extra nl_connect for one channel */
	will_return(__wrap_nl_connect, 0);
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	IPCON_HANDLER handler =
		ipcon_create_handler(peer_name, LIBIPCON_FLG_DEFAULT);
	assert_non_null(handler);

	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	assert_non_null(iph);

	/* Default flags should set RCV_IF and SND_IF */
	assert_true(iph->flags & IPH_FLG_RCV_IF);
	assert_true(iph->flags & IPH_FLG_SND_IF);

	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, strdup_peer_name);
	will_return(__wrap__test_free, false);
	ipcon_free_handler(handler);
}

static void create_handler_no_flags(void **state)
{
	char *peer_name = "noflag_test";
	char *strdup_peer_name = "noflag_test";
	char iph_mem[1024];

	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, iph_mem);

	will_return(__wrap_strdup, 1);
	expect_string(__wrap_strdup, s, peer_name);
	will_return(__wrap_strdup, strdup_peer_name);

	/* Only c_chan init, no s_chan/r_chan */
	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	IPCON_HANDLER handler = ipcon_create_handler(peer_name, 0);

	assert_non_null(handler);

	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	assert_non_null(iph);

	/* Without flags, only c_chan is initialized */
	assert_false(iph->flags & IPH_FLG_RCV_IF);
	assert_false(iph->flags & IPH_FLG_SND_IF);

	assert_int_equal(ipcon_get_read_fd(handler), -EPERM);
	assert_int_equal(ipcon_get_write_fd(handler), -EPERM);

	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, strdup_peer_name);
	will_return(__wrap__test_free, false);
	ipcon_free_handler(handler);
}

static void free_handler_null(void **state)
{
	/* Should not crash */
	ipcon_free_handler(NULL);
}

/*
 * Async rcv tests
 */

static void async_rcv_null_args(void **state)
{
	struct async_rcv_ctl arc;

	assert_int_equal(ipcon_async_rcv(NULL, &arc), -EINVAL);
	assert_int_equal(ipcon_async_rcv((IPCON_HANDLER)0x1, NULL), -EINVAL);

	/* Calling stop with NULL should not crash */
	ipcon_async_rcv_stop(NULL);
}

int ipcon_tests_run(void *state)
{
	static struct CMUnitTest tests[] = {
		/* selfname tests */
		cmocka_unit_test(selfname_with_name),
		cmocka_unit_test(selfname_auto_peer),

		/* fd tests */
		cmocka_unit_test(get_read_fd_null_handler),
		cmocka_unit_test(get_write_fd_null_handler),

		/* Null/invalid handler tests */
		cmocka_unit_test(rcv_null_handler),
		cmocka_unit_test(send_null_handler),
		cmocka_unit_test(register_null_handler),
		cmocka_unit_test(join_null_handler),
		cmocka_unit_test(api_invalid_names),
		cmocka_unit_test(api_null_msg),
		cmocka_unit_test(send_invalid_args),

		/* create_handler variations */
		cmocka_unit_test(create_handler_default_flags),
		cmocka_unit_test(create_handler_no_flags),

		/* free_handler */
		cmocka_unit_test(free_handler_null),

		/* async */
		cmocka_unit_test(async_rcv_null_args),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
