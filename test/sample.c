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
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>

//open()
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

//read()
#include <unistd.h>

// should be last
#include <cmocka.h>

struct data {
	int i_data;
	char *p_data;
};

struct data *read_data(void)
{
	int fd = 0;
	struct data *result = NULL;

	while (1) {
		struct data *d = malloc(sizeof(*d));
		if (!d)
			break;

		fd = open("/tmp/abc", O_RDONLY);
		if (fd < 0)
			break;

		int ret = read(fd, d, sizeof(*d));
		if (ret == sizeof(*d))
			result = d;

		break;
	}

	if (fd > 0) {
		close(fd);
	}

	return result;
}

static void read_data_malloc_fail(void **state)
{
	will_return(__wrap_malloc, 0);
	will_return(__wrap_malloc, NULL);

	struct data *d = read_data();
	assert_null(d);
}

static void read_data_open_fail(void **state)
{
	struct data d = {
		.i_data = 10,
		.p_data = NULL,
	};
	will_return(__wrap_malloc, 0);
	will_return(__wrap_malloc, &d);
	will_return(__wrap_open, -1);
	will_return(__wrap_open, ENOENT);

	struct data *d1 = read_data();
	assert_null(d1);
}

static void read_data_read_fail(void **state)
{
	struct data d = {
		.i_data = 10,
		.p_data = NULL,
	};
	will_return(__wrap_malloc, 0);
	will_return(__wrap_malloc, &d);
	will_return(__wrap_open, 2);
	will_return(__wrap_read, -1);
	will_return(__wrap_read, EIO);
	will_return(__wrap_close, 0);

	struct data *d1 = read_data();
	assert_null(d1);
}

static void read_data_success(void **state)
{
	struct data d = {
		.i_data = 10,
		.p_data = NULL,
	};
	will_return(__wrap_malloc, 0);
	will_return(__wrap_malloc, &d);
	will_return(__wrap_open, 2);
	will_return(__wrap_read, sizeof(d));
	will_return(__wrap_close, 0);

	struct data *d1 = read_data();
	assert_non_null(d1);
	assert_int_equal(d1->i_data, 10);
	assert_null(d1->p_data);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(read_data_malloc_fail),
		cmocka_unit_test(read_data_open_fail),
		cmocka_unit_test(read_data_read_fail),
		cmocka_unit_test(read_data_success),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
