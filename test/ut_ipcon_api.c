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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>

#include "ut.h"
#include "libipcon.h"
#include "libipcon_priv.h"

/*
 * is_peer_present tests
 * is_peer_present creates a PEER_RESLOVE message and sends it via c_chan.
 * The mock for nl_send_auto controls the send result, and the mock for
 * nl_recvmsgs_default controls the receive/ack result.
 *
 * 0 return = peer found, non-zero = peer not found or error
 */

static void is_peer_present_with_rcv_if(void **state)
{
	char *peer_name = "client_a";
	char *strdup_peer_name = "client_a";
	char *server_name = "server_b";
	char iph_mem[1024];

	/* Create handler with default flags */
	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, iph_mem);

	will_return(__wrap_strdup, 1);
	expect_string(__wrap_strdup, s, peer_name);
	will_return(__wrap_strdup, strdup_peer_name);

	/* c_chan init: cb_alloc, socket_alloc_cb, nl_connect */
	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);

	/* s_chan init: another cb_alloc, socket_alloc_cb, nl_connect */
	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);

	/* r_chan init: another set */
	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);

	/* chan init: PEER_REG send_rcv */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0); /* cb_valid */
	will_return(__wrap_nl_recvmsgs_default, 1); /* cb_ack */
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0); /* success */

	IPCON_HANDLER handler =
		ipcon_create_handler(peer_name, LIBIPCON_FLG_DEFAULT);
	assert_non_null(handler);

	/* is_peer_present: PEER_RESLOVE send_rcv - peer found */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	int ret = is_peer_present(handler, server_name);
	assert_int_equal(ret, 0);

	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, strdup_peer_name);
	will_return(__wrap__test_free, false);
	ipcon_free_handler(handler);
}

static void is_peer_present_notfound(void **state)
{
	char *peer_name = "client_a";
	char *strdup_peer_name = "client_a";
	char *server_name = "nonexistent_server";
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

	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);

	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);

	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	IPCON_HANDLER handler =
		ipcon_create_handler(peer_name, LIBIPCON_FLG_DEFAULT);
	assert_non_null(handler);

	/* Simulate nl_send_auto failing (peer not found) */
	will_return(__wrap_nl_send_auto, -ENOENT);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	int ret = is_peer_present(handler, server_name);
	assert_int_not_equal(ret, 0);

	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, strdup_peer_name);
	will_return(__wrap__test_free, false);
	ipcon_free_handler(handler);
}

/*
 * Register/unregister group with invalid name
 */

static void register_group_invalid_name(void **state)
{
	char *peer_name = "grp_test";
	char *strdup_peer_name = "grp_test";
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

	/* Without SND_IF, register_group fails */
	assert_int_equal(ipcon_register_group(handler, ""), -EINVAL);
	assert_int_equal(ipcon_register_group(handler, NULL), -EINVAL);
	assert_int_equal(ipcon_unregister_group(handler, ""), -EINVAL);
	assert_int_equal(ipcon_unregister_group(handler, NULL), -EINVAL);

	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, strdup_peer_name);
	will_return(__wrap__test_free, false);
	ipcon_free_handler(handler);
}

/*
 * rcv variants with no RCV_IF
 */

static void rcv_no_rcv_if(void **state)
{
	char *peer_name = "sendonly_test";
	char *strdup_peer_name = "sendonly_test";
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

	/* Without RCV_IF, all rcv variants should fail */
	{
		struct ipcon_msg im;
		assert_int_equal(ipcon_rcv(handler, &im), -EPERM);
		assert_int_equal(ipcon_rcv_nonblock(handler, &im), -EPERM);
		assert_int_equal(ipcon_rcv_timeout(handler, &im, NULL), -EPERM);
	}

	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, strdup_peer_name);
	will_return(__wrap__test_free, false);
	ipcon_free_handler(handler);
}

/*
 * is_group_present tests
 */

static void is_group_present_null_args(void **state)
{
	assert_int_equal(is_group_present(NULL, "peer", "grp"), -EINVAL);
	assert_int_equal(is_group_present((IPCON_HANDLER)0x1, NULL, "grp"),
			 -EINVAL);
	assert_int_equal(is_group_present((IPCON_HANDLER)0x1, "peer", NULL),
			 -EINVAL);
}

/*
 * ipcon_join/leave_group null/error tests
 */

static void join_leave_no_rcv_if(void **state)
{
	char *peer_name = "nojoin_test";
	char *strdup_peer_name = "nojoin_test";
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

	/* Without RCV_IF, join/leave fail */
	assert_int_equal(ipcon_join_group(handler, "peer", "grp"), -EPERM);
	assert_int_equal(ipcon_leave_group(handler, "peer", "grp"), -EPERM);

	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, strdup_peer_name);
	will_return(__wrap__test_free, false);
	ipcon_free_handler(handler);
}

int ipcon_api_tests_run(void *state)
{
	static struct CMUnitTest tests[] = {
		/* is_peer_present tests */
		cmocka_unit_test(is_peer_present_with_rcv_if),
		cmocka_unit_test(is_peer_present_notfound),

		/* Group operations */
		cmocka_unit_test(register_group_invalid_name),
		cmocka_unit_test(is_group_present_null_args),
		cmocka_unit_test(join_leave_no_rcv_if),

		/* rcv */
		cmocka_unit_test(rcv_no_rcv_if),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
