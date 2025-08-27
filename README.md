# LIBIPCON

[![Version](https://img.shields.io/badge/version-0.0.1-blue)](https://github.com/saimizi/libipcon)
[![License](https://img.shields.io/badge/license-LGPLv2.1-green)](LICENSE)
[![Build](https://img.shields.io/badge/build-cmake%20%7C%20meson-orange)](BUILD.md)

**LIBIPCON (IPC Over Netlink)** is a high-performance, packet-based IPC mechanism built on Linux netlink sockets. It provides efficient message communication among multiple local processes with support for both unicast and multicast messaging, automatic peer discovery, and event notifications.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [API Documentation](#api-documentation)
- [Building from Source](#building-from-source)
- [Testing](#testing)
- [Components](#components)
- [License](#license)

## Features

- **🚀 High Performance**: Built on Linux netlink for efficient kernel-space communication
- **📦 Packet-Based**: Message boundaries are preserved - receive complete messages or nothing
- **🔄 Flexible Communication Patterns**:
  - One-to-One (Client-Server)
  - One-to-Many (Publisher-Subscriber)
  - Many-to-One (Event Aggregation)
- **🔍 Automatic Peer Discovery**: Detect when peers join or leave the network
- **⚡ Multiple Reception Modes**:
  - Blocking reception
  - Non-blocking reception  
  - Timeout-based reception
  - Asynchronous callback-based reception
- **🏷️ Group Management**: Create and manage message groups for multicast communication
- **📊 Event Notifications**: Get notified of peer and group lifecycle events
- **🔧 Poll/Select Support**: File descriptor access for integration with event loops

## Architecture

LIBIPCON consists of several key components:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │   Application   │    │   Application   │
│   (Client A)    │    │   (Server)      │    │   (Client B)    │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │     LIBIPCON Library      │
                    │   (Userspace Library)     │
                    └─────────────┬─────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │     Linux Netlink         │
                    │   (Kernel Interface)      │
                    └─────────────┬─────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │     IPCON Driver          │
                    │   (Kernel Module)         │
                    └───────────────────────────┘
```

## Requirements

- **Operating System**: Linux (kernel 3.0+)
- **Dependencies**:
  - `libnl-genl-3.0` - Netlink Generic Library
  - `libc` - Standard C Library
- **Build Tools**:
  - GCC or Clang compiler
  - CMake 3.10+ OR Meson 0.50+
  - pkg-config
- **Kernel Module**: IPCON kernel driver (loaded via `modprobe ipcon`)

## Installation

### Package Installation (Recommended)
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install libnl-genl-3-dev pkg-config

# Install dependencies (CentOS/RHEL/Fedora)
sudo yum install libnl3-genl-devel pkgconfig
# OR
sudo dnf install libnl3-genl-devel pkgconfig
```

### From Source
```bash
git clone https://github.com/saimizi/libipcon.git
cd libipcon
mkdir build && cd build
cmake ..
make
sudo make install
```

## Quick Start

Here's a simple example showing basic libipcon usage:

### Server Application
```c
#include "libipcon.h"
#include <stdio.h>

int main() {
    // Create handler
    IPCON_HANDLER handler = ipcon_create_handler("my_server", LIBIPCON_FLG_DEFAULT);
    if (!handler) {
        printf("Failed to create handler\n");
        return -1;
    }

    // Receive messages
    struct ipcon_msg msg;
    while (1) {
        if (ipcon_rcv(handler, &msg) == 0) {
            printf("Received from %s: %.*s\n", msg.peer, msg.len, msg.buf);
            
            // Echo back
            ipcon_send_unicast(handler, msg.peer, "ACK", 3);
        }
    }

    ipcon_free_handler(handler);
    return 0;
}
```

### Client Application
```c
#include "libipcon.h"
#include <stdio.h>
#include <string.h>

int main() {
    // Create handler
    IPCON_HANDLER handler = ipcon_create_handler("my_client", LIBIPCON_FLG_DEFAULT);
    if (!handler) return -1;

    // Send message
    char message[] = "Hello Server!";
    if (ipcon_send_unicast(handler, "my_server", message, strlen(message)) < 0) {
        printf("Failed to send message\n");
    }

    // Wait for response
    struct ipcon_msg response;
    if (ipcon_rcv(handler, &response) == 0) {
        printf("Server replied: %.*s\n", response.len, response.buf);
    }

    ipcon_free_handler(handler);
    return 0;
}
```

## Usage Examples

### Group Multicast Communication
```c
// Publisher
IPCON_HANDLER pub = ipcon_create_handler("publisher", LIBIPCON_FLG_DEFAULT);
ipcon_register_group(pub, "news_feed");

char news[] = "Breaking: New LIBIPCON release!";
ipcon_send_multicast(pub, "news_feed", news, strlen(news), 1);

// Subscriber
IPCON_HANDLER sub = ipcon_create_handler("subscriber", LIBIPCON_FLG_DEFAULT);
ipcon_join_group(sub, "publisher", "news_feed");

struct ipcon_msg msg;
if (ipcon_rcv(sub, &msg) == 0) {
    printf("News: %.*s\n", msg.len, msg.buf);
}
```

### Asynchronous Message Handling
```c
void message_handler(char *peer_name, void *buf, uint32_t len, void *data) {
    printf("Async message from %s: %.*s\n", peer_name, len, (char*)buf);
}

void peer_added_handler(char *peer_name, void *data) {
    printf("Peer %s joined the network\n", peer_name);
}

struct async_rcv_ctl arc = {
    .cb = {
        .normal_msg_cb = message_handler,
        .peer_add = peer_added_handler,
        .data = NULL
    }
};

ipcon_async_rcv(handler, &arc);
// Messages are now handled asynchronously
```

## API Documentation

Complete API documentation is available in [`Document/libipcon-api.md`](Document/libipcon-api.md).

**Core Functions:**
- Handler Management: `ipcon_create_handler()`, `ipcon_free_handler()`
- Messaging: `ipcon_send_unicast()`, `ipcon_send_multicast()`, `ipcon_rcv()`
- Group Management: `ipcon_register_group()`, `ipcon_join_group()`
- Async Support: `ipcon_async_rcv()`, `ipcon_get_read_fd()`

## Building from Source

### Using CMake
```bash
mkdir build && cd build
cmake .. [OPTIONS]
make
```

**CMake Options:**
- `-DUNIT_TEST=ON` - Build unit tests
- `-DBUILD_LOGGER=ON` - Build logger utilities
- `-DBUILD_SAMPLES=ON` - Build sample applications

### Using Meson
```bash
meson setup build [OPTIONS]
meson compile -C build
```

**Meson Options:**
- `-Dunit_test=true` - Build unit tests
- `-Dbuild_logger=true` - Build logger utilities  
- `-Dbuild_sample=true` - Build sample applications
- `-Denable_coverage=true` - Enable test coverage
- `-Denable_nl_mock=true` - Enable netlink mocking for tests

## Testing

### Unit Tests
```bash
# CMake
mkdir build && cd build
cmake -DUNIT_TEST=ON ..
make
./test/ut_main

# Meson
meson setup build -Dunit_test=true
meson test -C build
```

### Integration Tests
```bash
cd samples
./test.sh
```

### Coverage Report
```bash
# Meson with coverage
meson setup build -Dunit_test=true -Denable_coverage=true
meson test -C build
ninja -C build coverage
```

## Components

### Library (`lib/`)
- `libipcon.c/h` - Main library implementation
- `libipcon_priv.c/h` - Private implementation details
- `libipcon_dbg.c/h` - Debug utilities
- `util.c/h` - Utility functions

### Logger (`logger/`)
- `ipcon_logger.c/h` - Message logging utilities
- `ipcon_cmd.c` - Command-line interface
- `ipcon_kevent.c` - Kernel event monitoring

### Samples (`samples/`)
- `ipcon_server.c` - Server example with group messaging
- `ipcon_sender.c` - Client example with unicast messaging
- `ipcon_user.c` - User interaction example
- `ipcon_test.c` - Comprehensive test application

### Tests (`test/`)
- Unit tests with mocking support
- Coverage reporting
- Mock libraries for netlink

## License

This project is licensed under the GNU Lesser General Public License v2.1 - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [`Document/libipcon-api.md`](Document/libipcon-api.md)
- **Issues**: [GitHub Issues](https://github.com/saimizi/libipcon/issues)
- **Discussions**: [GitHub Discussions](https://github.com/saimizi/libipcon/discussions)

---

**Note**: Make sure the IPCON kernel module is loaded (`sudo modprobe ipcon`) before using the library.