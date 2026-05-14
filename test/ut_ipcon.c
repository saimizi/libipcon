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
 * Helper: mock setup for a single-channel (flags=0) create_handler.
 * iph is real-allocated, strdup returns static buffer.
 * Provides extra nl_recvmsgs_default slots for auto-ack retries.
 */
static void expect_create_handler_named_single(char **strdup_out)
{
	static char namebuf[32];
	strcpy(namebuf, "test_peer");
	*strdup_out = namebuf;

	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, true);

	will_return(__wrap_strdup, 1);
	expect_string(__wrap_strdup, s, "test_peer");
	will_return(__wrap_strdup, *strdup_out);

	/* c_chan init */
	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);

	/* PEER_REG send_rcv (8 rounds for auto-ack safety) */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
}

/*
 * ipcon_selfname tests
 */

static void selfname_with_name(void **state)
{
	char *strdup_peer_name = NULL;

	expect_create_handler_named_single(&strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("test_peer", 0);
	assert_non_null(handler);

	const char *returned_name = ipcon_selfname(handler);
	assert_non_null(returned_name);
	assert_string_equal(returned_name, "test_peer");

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
 * Null/invalid handler tests
 * Only tests functions that properly NULL-check before dereference.
 */

static void rcv_null_handler(void **state)
{
	struct ipcon_msg im;

	assert_int_equal(ipcon_rcv(NULL, &im), -EINVAL);
	assert_int_equal(ipcon_rcv_nonblock(NULL, &im), -EINVAL);
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
	assert_int_equal(ipcon_register_group(NULL, NULL), -EINVAL);
	assert_int_equal(ipcon_unregister_group(NULL, NULL), -EINVAL);
}

static void leave_null_handler(void **state)
{
	assert_int_equal(ipcon_leave_group(NULL, "peer", "grp"), -EINVAL);
}

static void api_invalid_names(void **state)
{
	assert_int_equal(is_peer_present(NULL, "name"), -EINVAL);
	assert_int_equal(is_group_present(NULL, "peer", "grp"), -EINVAL);
}

static void api_trivial_checks(void **state)
{
	/* Functions that check !im or size before handler deref */
	assert_int_equal(ipcon_rcv((IPCON_HANDLER)0x1, NULL), -EINVAL);
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
	const char *peer_name = "default_test";
	static char sn1[32];
	strcpy(sn1, peer_name);

	/* Real alloc for iph */
	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, true);

	will_return(__wrap_strdup, 1);
	expect_string(__wrap_strdup, s, peer_name);
	will_return(__wrap_strdup, sn1);

	/* c_chan init */
	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);

	/* s_chan init (SND_IF) */
	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);

	/* r_chan init (RCV_IF) */
	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);

	/* PEER_REG send_rcv (8 rounds for auto-ack safety) */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	IPCON_HANDLER handler =
		ipcon_create_handler(peer_name, LIBIPCON_FLG_DEFAULT);
	assert_non_null(handler);

	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	assert_non_null(iph);

	assert_true(iph->flags & IPH_FLG_RCV_IF);
	assert_true(iph->flags & IPH_FLG_SND_IF);

	will_return(__wrap__test_free, false);
	ipcon_free_handler(handler);
}

static void create_handler_no_flags(void **state)
{
	const char *peer_name = "noflag_test";
	static char sn2[32];
	strcpy(sn2, peer_name);

	/* Real alloc for iph */
	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, true);

	will_return(__wrap_strdup, 1);
	expect_string(__wrap_strdup, s, peer_name);
	will_return(__wrap_strdup, sn2);

	/* c_chan init only */
	will_return(__wrap_nl_cb_alloc, 0);
	will_return(__wrap_nl_socket_alloc_cb, 0);
	expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
	will_return(__wrap_nl_connect, 0);

	/* PEER_REG send_rcv (8 rounds for auto-ack safety) */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	IPCON_HANDLER handler = ipcon_create_handler(peer_name, 0);
	assert_non_null(handler);

	struct ipcon_peer_handler *iph = handler_to_iph(handler);
	assert_non_null(iph);

	assert_false(iph->flags & IPH_FLG_RCV_IF);
	assert_false(iph->flags & IPH_FLG_SND_IF);

	assert_int_equal(ipcon_get_read_fd(handler), -EPERM);
	assert_int_equal(ipcon_get_write_fd(handler), -EPERM);

	will_return(__wrap__test_free, false);
	ipcon_free_handler(handler);
}

static void free_handler_null(void **state)
{
	ipcon_free_handler(NULL);
}

static void async_rcv_null_args(void **state)
{
	struct async_rcv_ctl arc;

	assert_int_equal(ipcon_async_rcv(NULL, &arc), -EINVAL);
	assert_int_equal(ipcon_async_rcv((IPCON_HANDLER)0x1, NULL), -EINVAL);
	ipcon_async_rcv_stop(NULL);
}

int ipcon_tests_run(void *state)
{
	static struct CMUnitTest tests[] = {
		cmocka_unit_test(selfname_with_name),
		cmocka_unit_test(selfname_auto_peer),

		cmocka_unit_test(get_read_fd_null_handler),
		cmocka_unit_test(get_write_fd_null_handler),

		cmocka_unit_test(rcv_null_handler),
		cmocka_unit_test(send_null_handler),
		cmocka_unit_test(register_null_handler),
		cmocka_unit_test(leave_null_handler),
		cmocka_unit_test(api_invalid_names),
		cmocka_unit_test(api_trivial_checks),

		cmocka_unit_test(create_handler_default_flags),
		cmocka_unit_test(create_handler_no_flags),

		cmocka_unit_test(free_handler_null),

		cmocka_unit_test(async_rcv_null_args),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
