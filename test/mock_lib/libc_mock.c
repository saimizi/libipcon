#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <assert.h>

// should be last
#include <cmocka.h>

int __attribute__((weak)) __wrap_open(const char *pathname, int flags)
{
	assert_non_null(pathname);
	assert_true(flags >= 0);

	int ret = mock_type(int);
	if (ret < 0) {
		errno = mock_type(int);
	}

	return ret;
}

void *__attribute__((weak)) __wrap_malloc(size_t size)
{
	assert_true(size > 0);

	int check = mock_type(int);
	if (check) {
		size_t max_size = mock_type(int);
		assert_true(size <= max_size);
	}

	return mock_type(void *);
}

ssize_t __attribute__((weak)) __wrap_read(int fd, void *buf, size_t count)
{
	assert_true(fd > 0);
	assert_true(buf != NULL);
	assert_true(count >= 0);

	int ret = mock_type(size_t);
	if (ret < 0)
		errno = mock_type(int);

	return ret;
}

int __attribute__((weak)) __wrap_close(int fd)
{
	assert_true(fd > 0);

	int ret = mock_type(int);

	if (ret < 0)
		errno = mock_type(int);

	return ret;
}

void __attribute__((weak)) __wrap_free(void *ptr)
{
	int check = mock_type(int);
	if (check) {
		void *expted_ptr = mock_type(void *);
		assert_true(ptr == expted_ptr);
	}
}

int __attribute__((weak)) no__wrap_printf(const char *format, ...)
{
	return 0;
}

int __attribute__((weak))
no__wrap_fprintf(FILE *stream, const char *format, ...)
{
	return 0;
}

int __attribute__((weak)) __wrap_ioctl(int fd, unsigned long request, ...)
{
	assert_true(fd >= 0);

	int ret = mock_type(int);
	if (ret < 0) {
		errno = mock_type(int);
	}
	return ret;
}

char *__attribute__((weak)) __wrap_strdup(const char *s)
{
	assert_non_null(s);
	int check = mock_type(int);
	if (check)
		check_expected(s);
	char *result = mock_type(char *);

	if (!result) {
		errno = ENOMEM;
	}

	return result;
}
