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
static void expect_handler_named_single(const char *peer_name,
					char **strdup_out)
{
	static char namebuf[32];
	strncpy(namebuf, peer_name, sizeof(namebuf) - 1);
	namebuf[sizeof(namebuf) - 1] = '\0';
	*strdup_out = namebuf;

	will_return(__wrap__test_malloc, false);
	will_return(__wrap__test_malloc, true);

	will_return(__wrap_strdup, 1);
	expect_string(__wrap_strdup, s, peer_name);
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

/* Dummy ACK callback for s_chan — sets ACK_OK to stop the AUTO_ACK loop. */
static int ack_ok(struct nl_msg *msg, void *arg)
{
	(void)msg;
	struct ipconmsg_result *ir = arg;
	ir->flags |= IR_FLG_ACK_OK;
	return NL_STOP;
}

/*
 * Helper: allocate a real s_chan socket for a single-channel handler
 * so ipcon_send_unicast / ipcon_send_multicast can run.
 *
 * Uses real libnl allocators, bypassing the mock layer, so no
 * will_return entries are consumed.  The ACK callback is a local
 * function that marks ACK_OK on s_chan.ir, preventing the AUTO_ACK
 * loop from spinning forever.
 */
static void init_s_chan_sk(struct ipcon_peer_handler *iph)
{
	extern struct nl_cb *__real_nl_cb_alloc(enum nl_cb_kind);
	extern struct nl_sock *__real_nl_socket_alloc_cb(struct nl_cb *);

	struct nl_cb *cb = __real_nl_cb_alloc(NL_CB_CUSTOM);
	assert_non_null(cb);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_ok, &iph->s_chan.ir);
	iph->s_chan.sk = __real_nl_socket_alloc_cb(cb);
	assert_non_null(iph->s_chan.sk);
	nl_cb_put(cb);
	iph->s_chan.ir.flags = 0;
	iph->s_chan.ir.msg = NULL;
	pthread_mutex_init(&iph->s_chan.mutex, NULL);
	iph->s_chan.mutex_initialized = true;
	iph->flags |= IPH_FLG_SND_IF;
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

	expect_handler_named_single("client_a", &strdup_peer_name);

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

	expect_handler_named_single("client_a", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("client_a", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		iph->flags |= IPH_FLG_SND_IF | IPH_FLG_RCV_IF;
	}

	/* Simulate nl_send_auto failing (peer not found) */
	will_return(__wrap_nl_send_auto, -ENOENT);

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

	expect_handler_named_single("grp_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("grp_test", 0);
	assert_non_null(handler);

	/* Without SND_IF, register/unregister fail. */
	assert_int_equal(ipcon_register_group(handler, ""), -EINVAL);
	assert_int_equal(ipcon_register_group(handler, NULL), -EINVAL);
	assert_int_equal(ipcon_unregister_group(handler, ""), -EINVAL);
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

	expect_handler_named_single("sendonly_test", &strdup_peer_name);

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

	expect_handler_named_single("nojoin_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("nojoin_test", 0);
	assert_non_null(handler);

	/* Without RCV_IF, join/leave fail */
	assert_int_equal(ipcon_join_group(handler, "peer", "grp"), -EPERM);
	assert_int_equal(ipcon_leave_group(handler, "peer", "grp"), -EPERM);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

/*
 * ipcon_send_unicast tests
 *
 * Sends IPCON_USR_MSG via s_chan with PEER_NAME and DATA attributes.
 * Requires IPH_FLG_SND_IF.  Uses single-channel handler +
 * init_s_chan_sk to set up s_chan without polluting the mock state.
 */

static void send_unicast_success(void **state)
{
	char *strdup_peer_name = NULL;
	char *target = "peer_b";
	char payload[] = "hello";

	expect_handler_named_single("send_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("send_test", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		init_s_chan_sk(iph);
	}

	/* send_unicast: IPCON_USR_MSG send_rcv on s_chan */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	int ret = ipcon_send_unicast(handler, target, payload,
				     strlen(payload) + 1);
	assert_int_equal(ret, 0);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void send_unicast_no_snd_if(void **state)
{
	char *strdup_peer_name = NULL;

	expect_handler_named_single("nosend_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("nosend_test", 0);
	assert_non_null(handler);

	assert_int_equal(ipcon_send_unicast(handler, "peer", "data", 4),
			 -EPERM);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void send_unicast_invalid_name(void **state)
{
	char *strdup_peer_name = NULL;

	expect_handler_named_single("iname_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("iname_test", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		init_s_chan_sk(iph);
	}

	assert_int_equal(ipcon_send_unicast(handler, "", "data", 4), -EINVAL);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void send_unicast_size_zero(void **state)
{
	char *strdup_peer_name = NULL;

	expect_handler_named_single("size0_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("size0_test", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		init_s_chan_sk(iph);
	}

	/* size == 0 should fail */
	assert_int_equal(ipcon_send_unicast(handler, "peer", "data", 0),
			 -EINVAL);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void send_unicast_size_too_large(void **state)
{
	char *strdup_peer_name = NULL;
	char big_payload[2049];

	memset(big_payload, 'x', sizeof(big_payload));

	expect_handler_named_single("big_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("big_test", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		init_s_chan_sk(iph);
	}

	/* size > MAX_IPCONMSG_DATA_SIZE should fail */
	assert_int_equal(ipcon_send_unicast(handler, "peer", big_payload,
					    sizeof(big_payload)),
			 -EINVAL);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

/*
 * ipcon_send_multicast tests
 *
 * Sends IPCON_MULTICAST_MSG via s_chan with GROUP_NAME and optional DATA/FLAG.
 * Requires IPH_FLG_SND_IF.
 */

static void send_multicast_success(void **state)
{
	char *strdup_peer_name = NULL;
	char *group_name = "mcast_grp";
	char payload[] = "group msg";

	expect_handler_named_single("mcast_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("mcast_test", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		init_s_chan_sk(iph);
	}

	/* send_multicast: IPCON_MULTICAST_MSG send_rcv on s_chan */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	int ret = ipcon_send_multicast(handler, group_name, payload,
				       strlen(payload) + 1, 0);
	assert_int_equal(ret, 0);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void send_multicast_sync(void **state)
{
	char *strdup_peer_name = NULL;
	char *group_name = "sync_grp";
	char payload[] = "sync msg";

	expect_handler_named_single("msync_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("msync_test", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		init_s_chan_sk(iph);
	}

	/* send_multicast with sync=1 */
	will_return(__wrap_nl_send_auto, 0);
	will_return(__wrap_nl_recvmsgs_default, 0);
	will_return(__wrap_nl_recvmsgs_default, 1);
	will_return(__wrap_nl_recvmsgs_default, NULL);
	will_return(__wrap_nl_recvmsgs_default, 0);

	int ret = ipcon_send_multicast(handler, group_name, payload,
				       strlen(payload) + 1, 1);
	assert_int_equal(ret, 0);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void send_multicast_no_snd_if(void **state)
{
	char *strdup_peer_name = NULL;

	expect_handler_named_single("nomcast_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("nomcast_test", 0);
	assert_non_null(handler);

	assert_int_equal(ipcon_send_multicast(handler, "grp", "data", 4, 0),
			 -EPERM);

	expect_free_handler(strdup_peer_name);
	ipcon_free_handler(handler);
}

static void send_multicast_invalid_name(void **state)
{
	char *strdup_peer_name = NULL;

	expect_handler_named_single("inmcast_test", &strdup_peer_name);

	IPCON_HANDLER handler = ipcon_create_handler("inmcast_test", 0);
	assert_non_null(handler);

	{
		struct ipcon_peer_handler *iph = handler_to_iph(handler);
		init_s_chan_sk(iph);
	}

	assert_int_equal(ipcon_send_multicast(handler, "", "data", 4, 0),
			 -EINVAL);

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

	expect_handler_named_single("reg_test", &strdup_peer_name);

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

	expect_handler_named_single("nosnd_test", &strdup_peer_name);

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

	expect_handler_named_single("unreg_test", &strdup_peer_name);

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

	expect_handler_named_single("nounreg_test", &strdup_peer_name);

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

		/* send_unicast */
		cmocka_unit_test(send_unicast_success),
		cmocka_unit_test(send_unicast_no_snd_if),
		cmocka_unit_test(send_unicast_invalid_name),
		cmocka_unit_test(send_unicast_size_zero),
		cmocka_unit_test(send_unicast_size_too_large),

		/* send_multicast */
		cmocka_unit_test(send_multicast_success),
		cmocka_unit_test(send_multicast_sync),
		cmocka_unit_test(send_multicast_no_snd_if),
		cmocka_unit_test(send_multicast_invalid_name),

		/* Group operations */
		cmocka_unit_test(is_group_present_null_args),
		cmocka_unit_test(join_leave_no_rcv_if),

		/* rcv */
		cmocka_unit_test(rcv_no_rcv_if),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
