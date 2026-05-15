/*
 * nl_mock_fixed.c — Per-socket callback storage override.
 *
 * The submodule mocklib/nl_mock.c stores callbacks in global variables,
 * so initialising multiple sockets (e.g. c_chan + s_chan + r_chan)
 * overwrites the ACK callback data.  When PEER_REG on c_chan calls
 * nl_recvmsgs_default, the ACK callback modifies the wrong channel's
 * result flags, causing the AUTO_ACK loop to never terminate.
 *
 * This file provides strong-symbol definitions that override the weak
 * symbols in mocklib/nl_mock.c.  Per-socket callbacks are staged by
 * cb pointer during nl_cb_set and committed to the socket when
 * nl_socket_alloc_cb creates it.
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

typedef struct {
	struct nl_sock *sk;
	nl_recvmsg_msg_cb_t valid;
	void *valid_data;
	nl_recvmsg_msg_cb_t ack;
	void *ack_data;
} mock_sock_cb;

#define MAX_MOCK_CBS 8
static mock_sock_cb sock_cbs[MAX_MOCK_CBS];
static int sock_cb_count = 0;

/* Staged registration keyed by cb pointer before the socket exists */
static struct {
	struct nl_cb *cb;
	int idx;
} cb2slot[MAX_MOCK_CBS];
static int cb2slot_n = 0;

static int slot_alloc(void)
{
	int n = sock_cb_count++;
	sock_cbs[n].sk = NULL;
	sock_cbs[n].valid = NULL;
	sock_cbs[n].valid_data = NULL;
	sock_cbs[n].ack = NULL;
	sock_cbs[n].ack_data = NULL;
	return n;
}

static int slot_by_cb(struct nl_cb *cb)
{
	for (int i = 0; i < cb2slot_n; i++)
		if (cb2slot[i].cb == cb)
			return cb2slot[i].idx;
	int n = slot_alloc();
	cb2slot[cb2slot_n].cb = cb;
	cb2slot[cb2slot_n].idx = n;
	cb2slot_n++;
	return n;
}

static int slot_by_sk(struct nl_sock *sk)
{
	for (int i = 0; i < sock_cb_count; i++)
		if (sock_cbs[i].sk == sk)
			return i;
	assert_true(0);
	return -1;
}

int __wrap_nl_recvmsgs_default(struct nl_sock *sk)
{
	assert_non_null(sk);
	int idx = slot_by_sk(sk);

	int do_valid = mock_type(int);
	if (do_valid && sock_cbs[idx].valid)
		sock_cbs[idx].valid(mock_ptr_type(struct nl_msg *),
				    sock_cbs[idx].valid_data);

	int do_ack = mock_type(int);
	if (do_ack && sock_cbs[idx].ack)
		sock_cbs[idx].ack(mock_ptr_type(struct nl_msg *),
				  sock_cbs[idx].ack_data);

	int ret = mock_type(int);
	return ret;
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
		sock_cbs[idx].valid = cb_func;
		sock_cbs[idx].valid_data = data;
	}
	if (type == NL_CB_ACK) {
		sock_cbs[idx].ack = cb_func;
		sock_cbs[idx].ack_data = data;
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
	sock_cbs[idx].sk = sk;
	return sk;
}
