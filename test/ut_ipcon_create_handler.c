#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/uinput.h>

//open()
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

//read()
#include <unistd.h>

#include "ut.h"

#include "libipcon.h"

extern void *__real_malloc(size_t size);

static void ipcon_create_handler_iph_malloc_fail(void **state)
{
	/* don't check max size */
	will_return(__wrap_malloc, 0);
	will_return(__wrap_malloc, NULL);
	IPCON_HANDLER handler = ipcon_create_handler(NULL, 0);
	assert_null(handler);
}

static void ipcon_create_handler_strdup_fail(void **state)
{
	char *peer_name = "ut_test";
	char iph_mem[1024];
	assert_non_null(iph_mem);

	/* don't check size */
	will_return(__wrap_malloc, 0);
	will_return(__wrap_malloc, iph_mem);

	/* check parameter */
	will_return(__wrap_strdup, 1);
	expect_string(__wrap_strdup, s, peer_name);

	will_return(__wrap_strdup, NULL);
	will_return(__wrap_free, 1);
	will_return(__wrap_free, iph_mem);

	IPCON_HANDLER handler = ipcon_create_handler(peer_name, 0);
	assert_null(handler);
}

static void ipcon_create_handler_auto_name_fail(void **state)
{
	char iph_mem[1024];
	/* don't specify peer name */
	char *peer_name = NULL;

	assert_non_null(iph_mem);
	will_return(__wrap_malloc, 0);
	will_return(__wrap_malloc, iph_mem);

	/* name buffer for auto peer name */
	will_return(__wrap_malloc, 1);
	will_return(__wrap_malloc, LIBIPCON_MAX_NAME_LEN);
	will_return(__wrap_malloc, NULL);

	will_return(__wrap_free, 1);
	will_return(__wrap_free, iph_mem);

	IPCON_HANDLER handler = ipcon_create_handler(peer_name, 0);
	assert_null(handler);
}

#include "libipcon_priv.h"
int __wrap_ipcon_chan_init(struct ipcon_peer_handler *iph)
{
	assert_non_null(iph);
	int check = mock_type(int);
	if (check) {
		check_expected(iph);
	}

	return mock_type(int);
}

static void ipcon_create_handler_chan_init_fail(void **state)
{
	char iph_mem[1024];
	/* don't specify peer name */
	char *peer_name = "ut_test";
	char *strdup_peer_name = "ut_test";

	assert_non_null(iph_mem);
	will_return(__wrap_malloc, 0);
	will_return(__wrap_malloc, iph_mem);

	/* check strdup parameter */
	will_return(__wrap_strdup, 1);
	expect_string(__wrap_strdup, s, peer_name);
	will_return(__wrap_strdup, strdup_peer_name);

	/* check ipcon_chan_init parameter */
	will_return(__wrap_ipcon_chan_init, 1);
	expect_value(__wrap_ipcon_chan_init, iph, iph_mem);
	will_return(__wrap_ipcon_chan_init, -1);

	/* free cloned peer name */
	will_return(__wrap_free, 1);
	will_return(__wrap_free, strdup_peer_name);

	/* free cloned iph_mem */
	will_return(__wrap_free, 1);
	will_return(__wrap_free, iph_mem);

	IPCON_HANDLER handler = ipcon_create_handler(peer_name, 0);
	assert_null(handler);
}

int ipcon_create_handler_run(void *)
{
	static struct CMUnitTest tests[] = {
		cmocka_unit_test(ipcon_create_handler_iph_malloc_fail),
		cmocka_unit_test(ipcon_create_handler_strdup_fail),
		cmocka_unit_test(ipcon_create_handler_auto_name_fail),
		cmocka_unit_test(ipcon_create_handler_chan_init_fail),
	};

	cmocka_run_group_tests(tests, NULL, NULL);
}
