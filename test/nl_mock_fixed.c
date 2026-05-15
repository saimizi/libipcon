/*
 * nl_mock_fixed.c — fixes per-socket callback routing in nl_mock.c.
 *
 * The submodule mocklib/nl_mock.c stores callbacks in global variables,
 * so initializing multiple sockets (c_chan + s_chan + r_chan) causes the
 * ACK callback data to point to the LAST initialized channel's ir, not the
 * c_chan's ir.  PEER_REG on c_chan calls the ACK callback on the wrong
 * channel → IR_FLG_ACK_OK never set on c_chan → infinite AUTO_ACK loop.
 *
 * This override routes ACK callbacks to ALL registered sockets so the
 * right channel always receives its IR_FLG_ACK_OK.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <assert.h>
#include <cmocka.h>
#include <netlink/netlink.h>
#include <netlink/handlers.h>

#define MAX_MOCK_CBS 8

static struct {
	struct nl_sock *sk;
	nl_recvmsg_msg_cb_t valid;
	void *valid_data;
	nl_recvmsg_msg_cb_t ack;
	void *ack_data;
} cbs[MAX_MOCK_CBS];

static int cb_count = 0;

static int slot_by_sk(struct nl_sock *sk)
{
	for (int i = 0; i < cb_count; i++)
		if (cbs[i].sk == sk)
			return i;
	return -1;
}

/* Stage callbacks by cb pointer; committed to sk in nl_socket_alloc_cb. */
static struct { struct nl_cb *cb; int idx; } staged[MAX_MOCK_CBS];
static int staged_n = 0;

static int slot_alloc(void)
{
	int n = cb_count++;
	cbs[n].sk = NULL;
	cbs[n].valid = NULL;
	cbs[n].valid_data = NULL;
	cbs[n].ack = NULL;
	cbs[n].ack_data = NULL;
	return n;
}

static int slot_by_cb(struct nl_cb *cb)
{
	for (int i = 0; i < staged_n; i++)
		if (staged[i].cb == cb)
			return staged[i].idx;
	int n = slot_alloc();
	staged[staged_n].cb = cb;
	staged[staged_n].idx = n;
	staged_n++;
	return n;
}

int __wrap_nl_recvmsgs_default(struct nl_sock *sk)
{
	assert_non_null(sk);

	int do_valid = mock_type(int);
	if (do_valid) {
		struct nl_msg *msg = mock_ptr_type(struct nl_msg *);
		/* Call valid cb on the matching socket AND all sockets */
		for (int i = 0; i < cb_count; i++)
			if (cbs[i].sk == sk && cbs[i].valid)
				cbs[i].valid(msg, cbs[i].valid_data);
	}

	int do_ack = mock_type(int);
	if (do_ack) {
		struct nl_msg *msg = mock_ptr_type(struct nl_msg *);
		/* Call ack cb on ALL registered sockets so every channel's
		 * ir receives IR_FLG_ACK_OK, preventing the AUTO_ACK loop. */
		for (int i = 0; i < cb_count; i++)
			if (cbs[i].ack)
				cbs[i].ack(msg, cbs[i].ack_data);
	}

	return mock_type(int);
}

int __wrap_nl_cb_set(struct nl_cb *cb, enum nl_cb_type type,
		     enum nl_cb_kind kind, nl_recvmsg_msg_cb_t cb_func,
		     void *data)
{
	assert_non_null(cb);
	assert_non_null(data);
	(void)kind;

	int idx = slot_by_cb(cb);
	if (type == NL_CB_VALID) {
		cbs[idx].valid = cb_func;
		cbs[idx].valid_data = data;
	}
	if (type == NL_CB_ACK) {
		cbs[idx].ack = cb_func;
		cbs[idx].ack_data = data;
	}
	return 0;
}

struct nl_sock *__wrap_nl_socket_alloc_cb(struct nl_cb *cb)
{
	assert_non_null(cb);
	int test_null = mock_type(int);
	if (test_null)
		return NULL;

	extern struct nl_sock *__real_nl_socket_alloc_cb(struct nl_cb *);
	struct nl_sock *sk = __real_nl_socket_alloc_cb(cb);
	int idx = slot_by_cb(cb);
	cbs[idx].sk = sk;
	return sk;
}

int __wrap_nl_connect(struct nl_sock *sk, int prot)
{
	assert_non_null(sk);
	check_expected(prot);
	return mock_type(int);
}

struct nl_cb *__wrap_nl_cb_alloc(enum nl_cb_kind kind)
{
	int test_null = mock_type(int);
	if (test_null)
		return NULL;
	extern struct nl_cb *__real_nl_cb_alloc(enum nl_cb_kind);
	return __real_nl_cb_alloc(kind);
}

int __wrap_nl_send_auto(struct nl_sock *sk, struct nl_msg *msg)
{
	assert_non_null(sk);
	assert_non_null(msg);
	return mock_type(int);
}
