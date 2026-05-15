# LIBIPCON Unit Tests

This document describes the unit testing infrastructure for libipcon,
how tests are structured, and how to add new tests.

## Test Framework: cmocka + mocklib

libipcon uses **cmocka** for unit testing with a custom **mocklib** submodule
for mocking libc and libnl functions.

- **cmocka** — Lightweight C unit testing framework with mock support
- **mocklib** (`test/mocklib/`) — Provides wrapped implementations of
  `malloc`, `free`, `strdup`, `nl_cb_alloc`, `nl_connect`, and more

The mocking is achieved via linker wrapping (`-Wl,--wrap=symbol`), which
intercepts calls to standard functions and redirects them to mock versions.

## Test Files

### `test/ut_ipcon_create_handler.c` (6 tests)

Tests for handler creation with various failure modes:

| Test | Description |
|------|-------------|
| `ipcon_create_handler_iph_malloc_fail` | malloc failure for handler struct |
| `ipcon_create_handler_strdup_fail` | strdup failure for peer name |
| `ipcon_create_handler_auto_name_fail` | Auto-name allocation failure |
| `ipcon_create_handler_chan_init_fail` | Netlink channel init failure |
| `ipcon_create_handler_peer_name` | Successful named handler creation |
| `ipcon_create_handler_auto_peer_name` | Successful auto-named handler |

### `test/ut_ipcon.c` (13 tests)

| Test | Description |
|------|-------------|
| `selfname_with_name` | ipcon_selfname returns correct name |
| `selfname_auto_peer` | ipcon_selfname with auto-generated name |
| `get_read_fd_null_handler` | ipcon_get_read_fd(NULL) returns -EBADF |
| `get_write_fd_null_handler` | ipcon_get_write_fd(NULL) returns -EBADF |
| `rcv_null_handler` | NULL handler checks for rcv variants |
| `send_null_handler` | NULL handler checks for send functions |
| `register_null_handler` | NULL handler checks for group registration |
| `leave_null_handler` | NULL handler check for leave_group |
| `api_invalid_names` | Invalid name checks for peer/group |
| `api_trivial_checks` | NULL msg and zero-size checks |
| `create_handler_no_flags` | Handler with flags=0 (no RCV/SND interfaces) |
| `free_handler_null` | ipcon_free_handler(NULL) should not crash |
| `async_rcv_null_args` | Null argument checks for async rcv |

## How Tests Work

### Mocking with cmocka

Tests set up mock expectations before calling library functions:

```c
// Tell the mock what to return when malloc is called
will_return(__wrap__test_malloc, false);  // don't check size
will_return(__wrap__test_malloc, true);   // do real allocation

// Tell the mock what to return when nl_connect is called
expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
will_return(__wrap_nl_connect, 0);
```

Mock functions consume will_return values in order. Each call to a mock
function uses one `will_return` per `mock_type()` call in the mock.

### Test groups

Tests are organized into groups via `cmocka_run_group_tests()`:

```c
int my_test_group(void *state)
{
    static struct CMUnitTest tests[] = {
        cmocka_unit_test(test_one),
        cmocka_unit_test(test_two),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
```

Test groups are registered in `ut_main.c`:

```c
int main(void)
{
    int ret = 0;
    ret = (ret == 0) ? ipcon_create_handler_run(NULL) : ret;
    ret = (ret == 0) ? ipcon_tests_run(NULL) : ret;
    return ret;
}
```

## Adding New Tests

### 1. Create a test function

```c
static void my_new_test(void **state)
{
    // Set up mocks
    will_return(__wrap__test_malloc, false);
    will_return(__wrap__test_malloc, true);
    
    // Call the function under test
    IPCON_HANDLER h = ipcon_create_handler("test", 0);
    
    // Assert the result
    assert_non_null(h);
    
    // Clean up with expected free calls
    will_return(__wrap__test_free, false);
    ipcon_free_handler(h);
}
```

### 2. Register in the test group

Add to the test list in your test file:

```c
int my_test_group(void *state)
{
    static struct CMUnitTest tests[] = {
        cmocka_unit_test(ipcon_create_handler_iph_malloc_fail),
        // ... existing tests ...
        cmocka_unit_test(my_new_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
```

### 3. Register in ut_main.c

```c
extern int my_test_group(void *);

int main(void)
{
    int ret = 0;
    ret = (ret == 0) ? ipcon_create_handler_run(NULL) : ret;
    ret = (ret == 0) ? ipcon_tests_run(NULL) : ret;
    ret = (ret == 0) ? my_test_group(NULL) : ret;
    return ret;
}
```

### 4. Add source file to CMakeLists.txt

In `test/CMakeLists.txt`:

```cmake
set(UT_SOURCES
    ut_main.c
    ut_ipcon_create_handler.c
    ut_ipcon.c
    my_new_test.c       # <-- add here
)
```

## Building and Running Tests

### CMake

```bash
cd libipcon
git submodule update --init --recursive
mkdir build && cd build
cmake -DUNIT_TEST=ON -DENABLE_NL_MOCK=ON ..
make -j$(nproc)
./test/ut_ipcon
```

### With coverage

```bash
cmake -DUNIT_TEST=ON -DENABLE_NL_MOCK=ON -DENABLE_COVERAGE=ON ..
make -j$(nproc)
./test/ut_ipcon
# Generate coverage report
lcov --capture --directory lib/CMakeFiles/ipcon.dir/ --output-file coverage.info
genhtml coverage.info --output-directory coverage
```

## Mock Reference

### Mocklib Functions (`test/mocklib/libc_mock.c`)

| Mock | Purpose | Will Return Values |
|------|---------|-------------------|
| `__wrap__test_malloc` | Intercepts `malloc` | check_size(bool), real_alloc(bool)\[, ptr(void*)\] |
| `__wrap__test_free` | Intercepts `free` | check(bool)\[, expected_ptr(void*)\] |
| `__wrap_strdup` | Intercepts `strdup` | check(int), result(char*) |
| `__wrap_open/close/read` | File operations | return value(int) |
| `__wrap_ioctl` | IO control | return value(int) |

### Netlink Mocks (`test/mocklib/nl_mock.c`)

| Mock | Purpose | Will Return Values |
|------|---------|-------------------|
| `__wrap_nl_cb_alloc` | Callback allocation | test_null(int) |
| `__wrap_nl_socket_alloc_cb` | Socket creation | test_null(int) |
| `__wrap_nl_connect` | Netlink connect | return value(int) |
| `__wrap_nl_send_auto` | Send message | return value(int) |
| `__wrap_nl_recvmsgs_default` | Receive messages | do_valid(int), \[msg(void*)\], do_ack(int), \[msg(void*)\], ret(int) |
| `__wrap_nl_cb_set` | Set callbacks | Stores CB_VALID/CB_ACK globally |

## Mock Patterns

### Simple success case (1 channel, flags=0)

```c
// malloc for handler struct
will_return(__wrap__test_malloc, false);   // check_size = false
will_return(__wrap__test_malloc, true);    // real_alloc = true

// strdup for peer name
will_return(__wrap_strdup, 1);              // check = true
expect_string(__wrap_strdup, s, "test");   // validate input
will_return(__wrap_strdup, "test");         // return static string

// c_chan init
will_return(__wrap_nl_cb_alloc, 0);         // 0 = call real function
will_return(__wrap_nl_socket_alloc_cb, 0);
expect_value(__wrap_nl_connect, prot, NETLINK_IPCON);
will_return(__wrap_nl_connect, 0);

// PEER_REG send_rcv
will_return(__wrap_nl_send_auto, 0);        // send success
will_return(__wrap_nl_recvmsgs_default, 0); // do_valid = 0 (skip)
will_return(__wrap_nl_recvmsgs_default, 1); // do_ack = 1 (do ack)
will_return(__wrap_nl_recvmsgs_default, NULL); // ack msg ptr
will_return(__wrap_nl_recvmsgs_default, 0); // return value

// Free handler (2 frees: name + iph)
will_return(__wrap__test_free, true);       // check = true
will_return(__wrap__test_free, "test");     // expected ptr (name)
will_return(__wrap__test_free, false);      // real free for iph
ipcon_free_handler(handler);
```

### Failure case (mock returns NULL)

```c
will_return(__wrap__test_malloc, false);
will_return(__wrap__test_malloc, false);    // real_alloc = false
will_return(__wrap__test_malloc, NULL);     // return NULL pointer

IPCON_HANDLER handler = ipcon_create_handler(...);
assert_null(handler);
```

## Tips for Writing Stable Tests

1. **Static buffers vs malloc** — For `strdup()` return values, use a
   static buffer (`static char buf[32]`) with `check=true` for the free mock.
   This avoids complex mock setups.

2. **Real allocation for structs** — Use `will_return(__wrap__test_malloc,
   false); will_return(__wrap__test_malloc, true);` for the handler struct
   itself. Stack buffers are too small for `sizeof(struct ipcon_peer_handler)`.

3. **Free mock patterns** — Each `free()` call in the library maps to one
   `__wrap__test_free` call. Track how many frees your function performs:
   - `ipcon_free_handler`: 2 frees (name + iph)
   - `ipcon_create_handler` failure path: 2 frees (name + iph)

4. **Netlink mock count** — The `nl_recvmsgs_default` mock is called once
   per `ipcon_send_rcv()` call. Each call consumes 4 will_return values.
   For 1 channel, you need 1 set. For 3 channels (LIBIPCON_FLG_DEFAULT),
   you need additional sets.

5. **Global state** — CB_VALID and CB_ACK are global variables in the mock.
   They persist between test functions within the same group. Each test
   should set them up fresh via `nl_cb_set`.

6. **Test isolation** — Cmocka resets mock state between test functions
   but not between test groups. If global state leaks between groups,
   add setup/teardown callbacks.

## CI Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs:

| Job | What it checks |
|-----|----------------|
| Code Style | clang-format on all .c/.h files |
| Build | Compile library with UNIT_TEST=OFF |
| Unit Tests + Coverage | Build with cmocka, run ut_ipcon, generate lcov coverage |

Submodules (`test/mocklib/`) are initialized via `git submodule update --init --recursive`.
