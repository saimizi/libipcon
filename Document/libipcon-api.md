# LIBIPCON Specification

## Table of Contents

- [Overview](#overview)
- [Constants and Definitions](#constants-and-definitions)
  - [Core Constants](#core-constants)
  - [Flags](#flags)
- [Data Structures](#data-structures)
  - [Message Types](#message-types)
  - [Kernel Event Types](#kernel-event-types)
  - [Main Message Structure](#main-message-structure)
- [API Functions](#api-functions)
  - [Handler Management](#handler-management)
    - [ipcon_create_handler](#ipcon_create_handler)
    - [ipcon_free_handler](#ipcon_free_handler)
    - [ipcon_selfname](#ipcon_selfname)
  - [Peer and Group Checking](#peer-and-group-checking)
    - [is_peer_present](#is_peer_present)
    - [is_group_present](#is_group_present)
  - [Group Management](#group-management)
    - [ipcon_register_group](#ipcon_register_group)
    - [ipcon_unregister_group](#ipcon_unregister_group)
    - [ipcon_join_group](#ipcon_join_group)
    - [ipcon_leave_group](#ipcon_leave_group)
    - [ipcon_find_group](#ipcon_find_group)
  - [Message Communication](#message-communication)
    - [ipcon_send_unicast](#ipcon_send_unicast)
    - [ipcon_send_multicast](#ipcon_send_multicast)
  - [Message Reception](#message-reception)
    - [ipcon_rcv](#ipcon_rcv)
    - [ipcon_rcv_nonblock](#ipcon_rcv_nonblock)
    - [ipcon_rcv_timeout](#ipcon_rcv_timeout)
  - [Asynchronous Communication](#asynchronous-communication)
    - [ipcon_async_rcv](#ipcon_async_rcv)
    - [ipcon_async_rcv_stop](#ipcon_async_rcv_stop)
  - [File Descriptor Access](#file-descriptor-access)
    - [ipcon_get_read_fd](#ipcon_get_read_fd)
    - [ipcon_get_write_fd](#ipcon_get_write_fd)
- [Callback Structure](#callback-structure)
  - [async_cb_ctl](#async_cb_ctl)
- [Complete Example](#complete-example)

## Overview

LIBIPCON (IPC Over Netlink) is a packet-based IPC mechanism built on Linux netlink to provide message communication among multiple local processes. It supports both one-to-one and one-to-many communications with peer detection capabilities.

## Constants and Definitions

### Core Constants
- `LIBIPCON_MAX_PAYLOAD_LEN`: 2048 - Maximum payload size
- `LIBIPCON_MAX_NAME_LEN`: 32 - Maximum name length for peers/groups
- `LIBIPCON_MAX_USR_GROUP`: 5 - Maximum user groups
- `LIBIPCON_KERNEL_NAME`: "ipcon" - Kernel module name
- `LIBIPCON_KERNEL_GROUP_NAME`: "ipcon_kevent" - Kernel event group name

### Flags
- `LIBIPCON_FLG_DISABLE_KEVENT_FILTER`: Disable kernel event filtering
- `LIBIPCON_FLG_USE_RCV_IF`: Use receive interface
- `LIBIPCON_FLG_USE_SND_IF`: Use send interface
- `LIBIPCON_FLG_DEFAULT`: Default flags (RCV_IF | SND_IF)

## Data Structures

### Message Types
```c
enum libipcon_msg_type {
    LIBIPCON_NORMAL_MSG,    // Normal peer-to-peer message
    LIBIPCON_GROUP_MSG,     // Group multicast message
    LIBIPCON_KEVENT_MSG,    // Kernel event message
    LIBIPCON_INVALID_MSG    // Invalid message type
};
```

### Kernel Event Types
```c
enum libipcon_kevent_type {
    LIBIPCON_EVENT_PEER_ADD,     // Peer added
    LIBIPCON_EVENT_PEER_REMOVE,  // Peer removed
    LIBIPCON_EVENT_GRP_ADD,      // Group added
    LIBIPCON_EVENT_GRP_REMOVE    // Group removed
};
```

### Main Message Structure
```c
struct ipcon_msg {
    enum libipcon_msg_type type;
    char group[LIBIPCON_MAX_NAME_LEN];
    char peer[LIBIPCON_MAX_NAME_LEN];
    uint32_t len;
    union {
        char buf[LIBIPCON_MAX_PAYLOAD_LEN];
        struct libipcon_kevent kevent;
    };
};
```

## API Functions

### Handler Management

#### ipcon_create_handler

| Aspect | Details |
|--------|---------|
| **Function** | `IPCON_HANDLER ipcon_create_handler(char *peer_name, unsigned long flags)` |
| **Description** | Creates a new IPCON handler for communication |
| **Parameters** | `char *peer_name` - Name of the peer (up to 32 characters)<br>`unsigned long flags` - Configuration flags (LIBIPCON_FLG_*) |
| **Return Value** | `IPCON_HANDLER` on success, NULL on failure |

##### Usage Example
```c
IPCON_HANDLER handler = ipcon_create_handler("my_peer", LIBIPCON_FLG_DEFAULT);
if (!handler) {
    // Handle error
}
```

#### ipcon_free_handler

| Aspect | Details |
|--------|---------|
| **Function** | `void ipcon_free_handler(IPCON_HANDLER handler)` |
| **Description** | Frees an IPCON handler and releases resources |
| **Parameters** | `IPCON_HANDLER handler` - Handler to free |
| **Return Value** | void |

##### Usage Example
```c
ipcon_free_handler(handler);
```

#### ipcon_selfname

| Aspect | Details |
|--------|---------|
| **Function** | `const char *ipcon_selfname(IPCON_HANDLER handler)` |
| **Description** | Returns the name of the current peer |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance |
| **Return Value** | `const char*` - peer name |

##### Usage Example
```c
const char *name = ipcon_selfname(handler);
printf("My name is: %s\n", name);
```

### Peer and Group Checking

#### is_peer_present

| Aspect | Details |
|--------|---------|
| **Function** | `int is_peer_present(IPCON_HANDLER handler, char *name)` |
| **Description** | Checks if a peer is currently present/active |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`char *name` - Name of peer to check |
| **Return Value** | 1 if present, 0 if not present, negative on error |

##### Usage Example
```c
if (is_peer_present(handler, "server_peer") > 0) {
    // Peer is available
}
```

#### is_group_present

| Aspect | Details |
|--------|---------|
| **Function** | `int is_group_present(IPCON_HANDLER handler, char *peer_name, char *group_name)` |
| **Description** | Checks if a peer is member of a specific group |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`char *peer_name` - Name of peer<br>`char *group_name` - Name of group |
| **Return Value** | 1 if present in group, 0 if not, negative on error |

##### Usage Example
```c
if (is_group_present(handler, "peer1", "my_group") > 0) {
    // Peer is in the group
}
```

### Group Management

#### ipcon_register_group

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_register_group(IPCON_HANDLER handler, char *name)` |
| **Description** | Registers a new message group |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`char *name` - Name of group to register |
| **Return Value** | 0 on success, negative error code on failure |

##### Usage Example
```c
int ret = ipcon_register_group(handler, "notification_group");
if (ret < 0) {
    // Handle registration error
}
```

#### ipcon_unregister_group

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_unregister_group(IPCON_HANDLER handler, char *name)` |
| **Description** | Unregisters a message group |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`char *name` - Name of group to unregister |
| **Return Value** | 0 on success, negative error code on failure |

##### Usage Example
```c
int ret = ipcon_unregister_group(handler, "notification_group");
```

#### ipcon_join_group

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_join_group(IPCON_HANDLER handler, char *srvname, char *grpname)` |
| **Description** | Joins a peer to a message group |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`char *srvname` - Name of server/peer to join<br>`char *grpname` - Name of group to join |
| **Return Value** | 0 on success, negative error code on failure |

##### Usage Example
```c
int ret = ipcon_join_group(handler, "server_peer", "notification_group");
```

#### ipcon_leave_group

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_leave_group(IPCON_HANDLER handler, char *srvname, char *grpname)` |
| **Description** | Removes a peer from a message group |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`char *srvname` - Name of server/peer to remove<br>`char *grpname` - Name of group to leave |
| **Return Value** | 0 on success, negative error code on failure |

##### Usage Example
```c
int ret = ipcon_leave_group(handler, "server_peer", "notification_group");
```

#### ipcon_find_group

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_find_group(IPCON_HANDLER handler, char *name, uint32_t *groupid)` |
| **Description** | Finds group ID by name |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`char *name` - Group name to find<br>`uint32_t *groupid` - Pointer to store group ID |
| **Return Value** | 0 on success, negative error code on failure |

##### Usage Example
```c
uint32_t group_id;
int ret = ipcon_find_group(handler, "my_group", &group_id);
if (ret == 0) {
    printf("Group ID: %u\n", group_id);
}
```

### Message Communication

#### ipcon_send_unicast

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_send_unicast(IPCON_HANDLER handler, char *name, void *buf, size_t size)` |
| **Description** | Sends a unicast message to a specific peer |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`char *name` - Name of target peer<br>`void *buf` - Message buffer<br>`size_t size` - Size of message |
| **Return Value** | 0 on success, negative error code on failure |

##### Usage Example
```c
char message[] = "Hello peer!";
int ret = ipcon_send_unicast(handler, "target_peer", message, strlen(message));
if (ret < 0) {
    // Handle send error
}
```

#### ipcon_send_multicast

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_send_multicast(IPCON_HANDLER handler, char *name, void *buf, size_t size, int sync)` |
| **Description** | Sends a multicast message to a group |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`char *name` - Name of target group<br>`void *buf` - Message buffer<br>`size_t size` - Size of message<br>`int sync` - Synchronous (1) or asynchronous (0) send |
| **Return Value** | 0 on success, negative error code on failure |

##### Usage Example
```c
char notification[] = "Group notification";
int ret = ipcon_send_multicast(handler, "notification_group",
                              notification, strlen(notification), 1);
```

### Message Reception

#### ipcon_rcv

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_rcv(IPCON_HANDLER handler, struct ipcon_msg *im)` |
| **Description** | Receives a message (blocking) |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`struct ipcon_msg *im` - Message structure to fill |
| **Return Value** | 0 on success, negative error code on failure |

##### Usage Example
```c
struct ipcon_msg msg;
int ret = ipcon_rcv(handler, &msg);
if (ret == 0) {
    printf("Received from %s: %.*s\n", msg.peer, msg.len, msg.buf);
}
```

#### ipcon_rcv_nonblock

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_rcv_nonblock(IPCON_HANDLER handler, struct ipcon_msg *im)` |
| **Description** | Receives a message (non-blocking) |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`struct ipcon_msg *im` - Message structure to fill |
| **Return Value** | 0 on success, -EAGAIN if no message, negative error code on failure |

##### Usage Example
```c
struct ipcon_msg msg;
int ret = ipcon_rcv_nonblock(handler, &msg);
if (ret == 0) {
    // Process message
} else if (ret == -EAGAIN) {
    // No message available
}
```

#### ipcon_rcv_timeout

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_rcv_timeout(IPCON_HANDLER handler, struct ipcon_msg *im, struct timeval *timeout)` |
| **Description** | Receives a message with timeout |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`struct ipcon_msg *im` - Message structure to fill<br>`struct timeval *timeout` - Timeout value |
| **Return Value** | 0 on success, negative error code on failure/timeout |

##### Usage Example
```c
struct ipcon_msg msg;
struct timeval timeout = {.tv_sec = 5, .tv_usec = 0}; // 5 second timeout
int ret = ipcon_rcv_timeout(handler, &msg, &timeout);
```

### Asynchronous Communication

#### ipcon_async_rcv

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_async_rcv(IPCON_HANDLER handler, struct async_rcv_ctl *arc)` |
| **Description** | Starts asynchronous message reception with callbacks |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance<br>`struct async_rcv_ctl *arc` - Async receive control structure |
| **Return Value** | 0 on success, negative error code on failure |

##### Usage Example
```c
void normal_msg_handler(char *peer_name, void *buf, uint32_t len, void *data) {
    printf("Message from %s: %.*s\n", peer_name, len, (char*)buf);
}

struct async_rcv_ctl arc = {
    .cb = {
        .normal_msg_cb = normal_msg_handler,
        .data = NULL
    }
};

int ret = ipcon_async_rcv(handler, &arc);
```

#### ipcon_async_rcv_stop

| Aspect | Details |
|--------|---------|
| **Function** | `void ipcon_async_rcv_stop(IPCON_HANDLER handler)` |
| **Description** | Stops asynchronous message reception |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance |
| **Return Value** | void |

##### Usage Example
```c
ipcon_async_rcv_stop(handler);
```

### File Descriptor Access

#### ipcon_get_read_fd

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_get_read_fd(IPCON_HANDLER handler)` |
| **Description** | Gets the read file descriptor for polling |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance |
| **Return Value** | File descriptor on success, negative error code on failure |

##### Usage Example
```c
int read_fd = ipcon_get_read_fd(handler);
if (read_fd >= 0) {
    // Use in poll/select/epoll
}
```

#### ipcon_get_write_fd

| Aspect | Details |
|--------|---------|
| **Function** | `int ipcon_get_write_fd(IPCON_HANDLER handler)` |
| **Description** | Gets the write file descriptor for polling |
| **Parameters** | `IPCON_HANDLER handler` - Handler instance |
| **Return Value** | File descriptor on success, negative error code on failure |

##### Usage Example
```c
int write_fd = ipcon_get_write_fd(handler);
if (write_fd >= 0) {
    // Use in poll/select/epoll
}
```

## Callback Structure

### async_cb_ctl
```c
struct async_cb_ctl {
    void (*normal_msg_cb)(char *peer_name, void *buf, uint32_t len, void *data);
    void (*group_msg_cb)(char *peer_name, char *group_name, void *buf, uint32_t len, void *data);
    void (*peer_add)(char *peer_name, void *data);
    void (*peer_remove)(char *peer_name, void *data);
    void (*group_add)(char *peer_name, char *group_name, void *data);
    void (*group_remove)(char *peer_name, char *group_name, void *data);
    void (*auto_group_join)(char *peer_name, char *group_name, void *data);
    void (*auto_group_leave)(char *peer_name, char *group_name, void *data);
    void (*rcv_msg_error)(int error, void *data);
    void *data;
};
```

## Complete Example

```c
#include "libipcon.h"
#include <stdio.h>

int main() {
    // Create handler
    IPCON_HANDLER handler = ipcon_create_handler("example_peer", LIBIPCON_FLG_DEFAULT);
    if (!handler) {
        printf("Failed to create handler\n");
        return -1;
    }

    // Register a group
    if (ipcon_register_group(handler, "example_group") < 0) {
        printf("Failed to register group\n");
        goto cleanup;
    }

    // Send a message
    char message[] = "Hello World";
    if (ipcon_send_unicast(handler, "target_peer", message, sizeof(message)) < 0) {
        printf("Failed to send message\n");
    }

    // Receive a message
    struct ipcon_msg msg;
    if (ipcon_rcv_nonblock(handler, &msg) == 0) {
        printf("Received: %.*s from %s\n", msg.len, msg.buf, msg.peer);
    }

cleanup:
    ipcon_free_handler(handler);
    return 0;
}
```
