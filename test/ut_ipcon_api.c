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
 * Helper: mock setup for a single-channel (flags=0) create_handler.
 * Uses the same proven pattern as ut_ipcon.c: iph is real-allocated,
 * strdup returns a static buffer.  free(check=true) for the static
 * buffer, free(check=false) for iph.
 */
static void expect_handler_named_single(char **strdup_out)
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

	/* PEER_REG send_rcv */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0); /* cb_valid */
	will_return(__wrap_nl_recvmsgs_default, 1); /* cb_ack */
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0); /* success */
}

static void expect_free_handler(char *strdup_peer_name)
{
	will_return(__wrap__test_free, true);
	will_return(__wrap__test_free, strdup_peer_name);
	will_return(__wrap__test_free, false);
}

/*
 * is_peer_present tests
 * is_peer_present creates a PEER_RESLOVE message and sends it via c_chan.
 * The mock for nl_send_auto controls the send result, and the mock for
 * nl_recvmsgs_default controls the receive/ack result.
 *
 * is_peer_present returns ret == 0 on success, i.e. 1 (truthy) =
 * peer found, 0 (falsy) = not present or error.
 */

static void is_peer_present_with_rcv_if(void **state)
{
	char *strdup_peer_name = NULL;
	char *server_name = "server_b";

	expect_handler_named_single(&strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("client_a", 0);
	assert_non_null(handler);

	/* Set s_chan + r_chan flags manually so the API passes its
	 * flag checks without actually initializing those channels. */
	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		iph->flags |= IPH_FLG_SND_IF | IPH_FLG_RCV_IF;
	}

	/* is_peer_present: PEER_RESLOVE send_rcv - peer found */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	int ret = is_peer_present(handler, server_name);
	assert_int_not_equal(ret, 0);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void is_peer_present_notfound(void **state)
{
	char *strdup_peer_name = NULL;
	char *server_name = "nonexistent_server";

	expect_handler_named_single(&strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("client_a", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		iph->flags |= IPH_FLG_SND_IF | IPH_FLG_RCV_IF;
	}

	/* Simulate nl_send_auto failing (peer not found) */
	will_return(__wrap_nl_send_auto, -ENOENT);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	int ret = is_peer_present(handler, server_name);
	assert_int_equal(ret, 0);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

/*
 * Register/unregister group with invalid name
 */

static void register_group_invalid_name(void **state)
{
	char *strdup_peer_name = NULL;

	expect_handler_named_single(&strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("grp_test", 0);
	assert_non_null(handler);

	/* Without SND_IF, register/unregister fail.
	 * Note: unregister_group checks SND_IF before name validity
	 * (unlike register_group which checks valid_name first), so
	 * unregister with empty name returns -EPERM, not -EINVAL. */
	assert_int_equal(ipcon_register_group(handler, ""), -EINVAL);
	assert_int_equal(ipcon_register_group(handler, NULL), -EINVAL);
	assert_int_equal(ipcon_unregister_group(handler, ""), -EPERM);
	assert_int_equal(ipcon_unregister_group(handler, NULL), -EINVAL);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

/*
 * rcv variants with no RCV_IF
 */

static void rcv_no_rcv_if(void **state)
{
	char *strdup_peer_name = NULL;

	expect_handler_named_single(&strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("sendonly_test", 0);
	assert_non_null(handler);

	/* Without RCV_IF, all rcv variants should fail */
	{
		struct ipcon_msg im;
		assert_int_equal(ipcon_rcv(handler, &im), -EPERM);
		assert_int_equal(ipcon_rcv_nonblock(handler, &im), -EPERM);
		assert_int_equal(ipcon_rcv_timeout(handler, &im, NULL), -EPERM);
	}

	expect_free_handler(strdup_peer_name);
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
	char *strdup_peer_name = NULL;

	expect_handler_named_single(&strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("nojoin_test", 0);
	assert_non_null(handler);

	/* Without RCV_IF, join/leave fail */
	assert_int_equal(ipcon_join_group(handler, "peer", "grp"), -EPERM);
	assert_int_equal(ipcon_leave_group(handler, "peer", "grp"), -EPERM);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

/*
 * ipcon_register_group / ipcon_unregister_group success paths
 *
 * register_group sends IPCON_GRP_REG via c_chan and expects ack.
 * unregister_group sends IPCON_GRP_UNREG via c_chan and expects ack.
 * Both require IPH_FLG_SND_IF.
 */

static void register_group_success(void **state)
{
	char *strdup_peer_name = NULL;
	char *group_name = "test_group";

	expect_handler_named_single(&strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("reg_test", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		iph->flags |= IPH_FLG_SND_IF;
	}

	/* register_group: IPCON_GRP_REG send_rcv */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	int ret = ipcon_register_group(handler, group_name);
	assert_int_equal(ret, 0);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void register_group_no_snd_if(void **state)
{
	char *strdup_peer_name = NULL;

	expect_handler_named_single(&strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("nosnd_test", 0);
	assert_non_null(handler);

	/* Without SND_IF, register_group should return -EPERM */
	assert_int_equal(ipcon_register_group(handler, "any_group"), -EPERM);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void unregister_group_success(void **state)
{
	char *strdup_peer_name = NULL;
	char *group_name = "my_group";

	expect_handler_named_single(&strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("unreg_test", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		iph->flags |= IPH_FLG_SND_IF;
	}

	/* unregister_group: IPCON_GRP_UNREG send_rcv */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	int ret = ipcon_unregister_group(handler, group_name);
	assert_int_equal(ret, 0);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void unregister_group_no_snd_if(void **state)
{
	char *strdup_peer_name = NULL;

	expect_handler_named_single(&strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("nounreg_test", 0);
	assert_non_null(handler);

	/* Without SND_IF, unregister_group should return -EPERM */
	assert_int_equal(ipcon_unregister_group(handler, "any_group"), -EPERM);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

int ipcon_api_tests_run(void *state)
{
	static struct CMUnitTest tests[] = {
		/* is_peer_present tests */
		cmocka_unit_test(is_peer_present_with_rcv_if),
		cmocka_unit_test(is_peer_present_notfound),

		/* register/unregister group */
		cmocka_unit_test(register_group_invalid_name),
		cmocka_unit_test(register_group_success),
		cmocka_unit_test(register_group_no_snd_if),
		cmocka_unit_test(unregister_group_success),
		cmocka_unit_test(unregister_group_no_snd_if),

		/* Group operations */
		cmocka_unit_test(is_group_present_null_args),
		cmocka_unit_test(join_leave_no_rcv_if),

		/* rcv */
		cmocka_unit_test(rcv_no_rcv_if),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
