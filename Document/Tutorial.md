# IPC Over Netlink (IPCON) Tutorial

LIBIPCON (IPC Over Netlink) is a packet-based IPC mechanism built on Linux netlink 
to provide efficient message communication among multiple local processes.

The contents of this tutorial are as follows:
- [What IPCON does NOT help with](#what-ipcon-does-not-help-with)
- [What IPCON does help with](#what-ipcon-does-help-with)
- [Terms Definition](#terms-definition)
- [Architectural Overview](#architectural-overview)
- [How to use](#how-to-use)
  - [Configuration and Compiling](#configuration-and-compiling)
  - [Create a handler](#create-a-handler)
  - [Register a group](#register-a-group)
  - [Receive a message](#receive-a-message)
  - [Send a message](#send-a-message)
  - [IPCON_KERNEL_GROUP message group](#ipcon_kernel_group-message-group)
- [Conclusion](#conclusion)
- [Appendix](#appendix)
  - [Samples](#samples)

## What IPCON does NOT help with

To save your time, I will first describe what IPCON does not help with. If
what you want to do falls into the following cases, it may not be a good idea to
spend time reading this tutorial and investigating IPCON anymore. :(

- **IPCON is for Linux only.**

  As the name suggests, IPCON is based on netlink which is a Linux kernel
  interface used for IPC. If you want IPC on other platforms, IPCON doesn't
  help.

- **IPCON is a packet-based IPC.**

  In IPCON, data is sent and received in the format of netlink messages, not streams.
  This means the data transferred in IPCON has clear boundaries. You can
  receive a complete message or not at all, but you cannot receive part of it.
  If you want stream-based IPC, Unix domain sockets are a good choice.

## What IPCON does help with

In this section, I will describe the advantages of using IPCON.

- **One/Many-to-One and One-to-Many (message multicasting) communications.**

  One/Many-to-One communication is normally used to implement a
  Server/Client model. One process serves as a server and there will be one or
  many clients to send requests to and get results from it.

  One-to-Many communication is needed when you want to implement a
  Provider/Subscriber model, in which a process serves as a provider.
  The provider is able to broadcast messages to many other processes called
  subscribers who are willing to receive messages from it. Subscribers receive
  the messages from the provider but do not send messages to it, just like the
  relationship between a newspaper company and its subscribers.

  Almost all well-known IPCs such as FIFO/Pipe, message queues, sockets, etc. are mainly
  designed for One/Many-to-One communication and do not support
  message multicasting. In order to implement a Provider/Subscriber model, you
  have to create multiple channels between the provider and the subscribers,
  which is often an unworthy effort.

  IPCON supports both kinds of communication and provides easy-to-use APIs
  to let user applications create their own message groups (as a provider) or
  receive messages from one or many specific message groups (as a subscriber).

- **Creation and disappearance detection of connected peers.**

  Often, it is not easy to find where the communication partner is or
  even more difficult to detect its abnormal termination. For example, when
  using a Unix domain socket, a socket file has to be created for communication
  partners to discover each other and set up communication. Since the socket
  file is exposed to the filesystem, every other user can also see it which
  may lead to security issues. Also, an application will never know the
  abnormal termination of the communication partner until it gets zero-size data
  from read() or gets an EPIPE error from write() as well as receiving a SIGPIPE
  signal.

  IPCON provides an asynchronous method to inform user applications of the
  creation and disappearance of a peer or a message group. The
  IPCON driver takes the role of managing peers and message groups. When a 
  group is registered by a user process, it sends event messages to user 
  applications through a special message group. Also by using the notify 
  callchain of the netlink system, the IPCON driver can detect the removal of 
  a connected peer and inform user applications.

  Also, in order to communicate with a peer, all you need is the peer name.
  This brings great flexibility in many cases.
  
- **Connectionless communication.**

  Compared to FIFO/Pipe, an advantage of System V/POSIX message queues is that
  messages are cached in the system so that a sender may send the message and
  exit as soon as possible without waiting for the completion of the receiver's
  reading. This kind of message caching is related to the issue of how to
  close communication safely. 

  As described above, IPCON is based on netlink which is a socket-based
  protocol. Every peer in IPCON has a socket interface and its own socket queue,
  so messages to a peer will be cached in its own socket queue. There is no
  specific channel built between the sender and the receiver. It is completely
  connectionless communication working in the same way as mail instead of
  telephone. So IPCON has the same advantage as message queues described above and
  avoids the risk of using system-wide resources like message queues at the same time.

- **Synchronous I/O multiplexing on file descriptors.**

  Since netlink is a socket-based protocol, IPCON provides socket file
  descriptors which can be used for synchronous I/O such as select().

## Terms Definition

In this section, the terms used in the IPCON description are explained.

- **Peer**

  A connection endpoint in the IPCON network. Each peer has a unique identifier
  and can send/receive messages.

- **Handler**

  An IPCON handler created by `ipcon_create_handler()` that represents a peer's
  connection to the IPCON system. All IPCON operations are performed through
  this handler.

- **Group**

  A message group identified by a unique name system-wide. A peer can create
  its own message group and multicast messages to peers who have subscribed
  to this group. Group names must be unique and are limited to 
  `LIBIPCON_MAX_NAME_LEN` (32 bytes).

## Architectural Overview

The diagram of IPCON is shown as follows:
```
	________ ________ ________
	|      | |      | |      |
	| App1 | |  ... | | AppN |
	|______| |______| |______|	libipcon APIs
    _ _ _ _ | _ _ _ _|_ _ _ _|_ _ _ _ _ _ _ _ _ _ _ _ 
	____|________|_______|____
	|			 |
	|	libipcon	 |
	|________________________|	
	____|________|______|____
    	|			 |	User space
    ----|    Kernel socket API	 |------------------
        |________________________|	Kernel space
	____|________|______|____	
	|			 |
	|   Netlink Subsystem    |
	|________________________|
	_____________|____________
	|			 |
	|    Generic Netlink 	 |
	|    protocol family	 |
	|________________________|
	_____________|___________
	|			 |
	|     IPCON Driver	 |
	|________________________|
```

- **IPCON Driver**

  The IPCON implementation in Linux kernel space. IPCON driver takes the role of
  managing services and groups registered by peers. IPCON driver is implemented
  as a Generic netlink protocol "IPCON". The API details of the IPCON driver can
  be found in "Documents/ipcon_driver/driver_api.txt" of IPCON software package.

- **Generic Netlink family**

  Netlink protocol family supports many protocols such as NETLINK_ROUTE for
  routing code, NETLINK_FIREWALL for netfilter codes and etc. Each protocol is
  assigned a unique protocol number as an identifier. While, since the maximum
  protocol number is limited to 32 (already 21 protocols have been assigned in
  linux-4.9 at present), it is in fact impossible to allocate a unique protocol
  number for every new netlink user. In order to deal with this problem, a
  Generic Netlink family module is introduced and used for multiplexing the
  communication channel of multiple new netlink users.

- **Netlink Subsystem**

  Netlink protocol implementation in Linux kernel.

- **Kernel socket API**

  Netlink is designed as a socket family protocol, So the communications between
  user and kernel space are via standard socket APIs such as socket(), recv()...

- **libipcon**

  A library implementation for IPCON. libipcon hides the internal netlink
  implementation details and provides easy-to-use APIs for user applications
  to communicate with each other. The API details of libipcon library can be found in
  "Document/libipcon-api.md" of the LIBIPCON software package.

In the following sections, the usage of IPCON is shown with example source
code.

## How to use

In this section, I will describe the usage of IPCON in general. As described
above, user applications do not communicate with the IPCON driver directly by
themselves and do not even need to know the details of the netlink protocol. They
use IPCON through the APIs of the libipcon library which are designed to
be thread-safe.

Ok, let's begin.

### Configuration and Compiling

LIBIPCON requires the following packages:

- GCC compiler and build tools (make, etc.)
- CMake 3.10+ OR Meson 0.50+
- libnl-genl-3.0 >= 3.2.27
  libipcon uses libnl for dealing with Generic netlink messages.
- pkg-config for dependency detection

#### Using CMake

In the source top directory, run the following commands to configure and compile
the LIBIPCON package:

```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

#### Using Meson

Alternatively, you can use Meson:

```bash
meson setup build
meson compile -C build
sudo meson install -C build
```

#### Build Options

Both build systems support various options:
- Unit tests: `cmake -DUNIT_TEST=ON` or `meson -Dunit_test=true`
- Sample applications: `cmake -DBUILD_SAMPLES=ON` or `meson -Dbuild_sample=true`
- Logger utilities: `cmake -DBUILD_LOGGER=ON` or `meson -Dbuild_logger=true`

If configuration and compilation succeed, you will get the following installed:

- `libipcon.so`: LIBIPCON shared library
- `libipcon.h`: LIBIPCON API header file
- Sample applications (if enabled)
- Logger utilities (if enabled)

**Note:** The kernel driver (`ipcon.ko`) must be loaded separately using modprobe.

### Create a handler

First of all, you need to create an IPCON handler to use LIBIPCON.

**Example: Create an IPCON handler**
```c
#include <stdio.h>
#include <stdlib.h>
#include "libipcon.h"

int main (int argc, char *argv[])
{
	IPCON_HANDLER handler;

	handler = ipcon_create_handler("my_peer", LIBIPCON_FLG_DEFAULT);
	if (!handler) {
		fprintf(stderr, "Failed to create handler\n");
		return 1;
	}

	/* ... do work ... */

	ipcon_free_handler(handler);
	return 0;
}
```

`ipcon_create_handler()` initializes the internal management structure and connects
to the IPCON driver. The function takes two parameters:
- `peer_name`: A unique name for this peer (up to 32 characters), or NULL for anonymous
- `flags`: Configuration flags (typically `LIBIPCON_FLG_DEFAULT`)

As you can see in `libipcon.h`, `IPCON_HANDLER` is defined as a `"void *"` pointer. 
When successful, `ipcon_create_handler()` returns a valid handler. If it fails 
(such as when `ipcon.ko` has not been loaded), it returns NULL.

To free an IPCON handler, call:
```c
ipcon_free_handler(handler);
```

Where "handler" is the IPCON handler created by `ipcon_create_handler()`.

**Note:**
    The peer name helps identify your process in the IPCON network. Other peers
    can discover and communicate with named peers using functions like 
    `is_peer_present()`. Anonymous peers (`peer_name = NULL`) can still communicate
    but cannot be discovered by name.

### Register a group

As described in "[What IPCON does help with](#what-ipcon-does-help-with)", IPCON supports multicast
messages, which is a kind of One-to-Many communication. A user process (for
example, called a "Provider") may set up its message group by calling the
`ipcon_register_group()` API. A group is identified by a system-wide unique name.
The maximum length of the group name is `LIBIPCON_MAX_NAME_LEN` (32 bytes).

**Example: Register a group**
```c
#define group_name "GroupX"

ret = ipcon_register_group(handler, group_name);
if (ret < 0)
	fprintf(stderr, "Failed to register group: %s (%d)\n",
		strerror(-ret), -ret);
```

`ipcon_register_group()` will return 0 if it succeeds and return a negative errno
number if it fails.

When a Provider decides to destroy a group it created, call
`ipcon_unregister_group()`:

```c
ipcon_unregister_group(handler, group_name);
```

Any process (called a "Subscriber") who is willing to receive messages from
this group may call `ipcon_join_group()`.

**Example: Join a group**
```c
ret = ipcon_join_group(handler, "provider_peer", "GroupX");
if (ret == 0)
	fprintf(stderr, "Joined %s group.\n", "GroupX");
```

The synopsis of `ipcon_join_group()` is as follows:

```c
int ipcon_join_group(IPCON_HANDLER handler, char *srvname, char *grpname);
```

The `handler` is the IPCON handler created by `ipcon_create_handler()`, `srvname`
is the name of the peer that owns the group, and `grpname` is the name of the 
group to join.

IPCON driver will cache the last group message of every registered group and
send (replay) it to all subscribers who specify `rcv_last_msg` as true in calling
`ipcon_join_group()`. The reason to do this is to help subscribers to avoid the
starvation state of a group message that represents some state information.
Assume that a Provider process creates a group "USB_EVENT" to inform Subscribers
of the USB insertion event. A new subscriber may join this group and do
something when it receives an "insert" event and do something else when it receives a
"remove" event. The code will be something like the following:

**Example: Problem of multicast message with a state information**
```c
ret = register_group("USB_EVENT");				// cond 1
if (ret == REG_OK) {
	while (!should_quit) {
		state = receive_from_group("USB_EVENT");	// cond 2

		if (state == "insert") {
			do_something();
			continue;
		} else if (state == "remove") {
			do_something_else();
			continue;
		}

		do_bad_state_error();
		should_quit = 1;
	};
}
```

If USB insertion is after cond 1, things will go well. But if USB insertion is
done before cond 1, this piece of code will miss the "insert" event completely
and will never run `do_something()` until next "USB inserting" action. This is a
kind of state starvation. This problem can be relieved by using `rcv_last_msg`
parameter of `ipcon_join_group()`. In this case, IPCON driver will replay the last
"insert" or "remove" message to Subscriber soon after it joined "USB_EVENT"
message group. That is, the present state of USB insertion is being reproduced
to the Subscriber.

When a Subscriber decides not to subscribe a group anymore, call
`ipcon_leave_group()`:

```c
ipcon_leave_group(handler, "provider_peer", "GroupX");
```

**Note:**
    When a Provider unregisters a group, Subscriber should detect it and call
    `ipcon_leave_group()` explicitly to unsubscribe the message. IPCON driver's
    IPCON_KERNEL_GROUP group message can be used to detect group unregister event.

### Receive a message

As described above, we may receive messages from a peer or a group. To identify
the source of the message, the following information is needed when a message is
received.

1. Is this message from a peer? or from a group that we subscribed ?
2. If the message is from a peer, what is the port number of peer who sent it ?
3. If the message is from a group, since we may subscribe many groups, from which
   group this message comes ?
4. What is the size of message data? and where to get the data?

In order to get all information described above, the received message is
represented in the following structure.

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

- `type`
  Indicates the type of received message:
  - `LIBIPCON_NORMAL_MSG`:	A message from a peer
  - `LIBIPCON_GROUP_MSG`:	A message from a group
  - `LIBIPCON_KEVENT_MSG`:	A kernel event message

- `group`
  Indicates the group name from which the message was sent.
  This is only valid when type is `LIBIPCON_GROUP_MSG`.

- `peer`
  Indicates the name of the peer who sent the message.
  This is valid for both `LIBIPCON_NORMAL_MSG` and `LIBIPCON_GROUP_MSG`.

- `len`
  The length of the message data.

- `buf`
  The message data (up to `LIBIPCON_MAX_PAYLOAD_LEN` = 2048 bytes).

- `kevent`
  Kernel event data (only valid when type is `LIBIPCON_KEVENT_MSG`).

libipcon's API `ipcon_rcv()` is used to receive a message:

```c
int ipcon_rcv(IPCON_HANDLER handler, struct ipcon_msg *im);
```

If successful, `ipcon_rcv()` saves received data in the buffer specified by `im` and
returns 0. If it fails, a negative errno code is returned. Unlike the APIs
described above, `ipcon_rcv()` will block if no message is received. The
format of receiving a message will be something like the following:

**Example: Receive messages**
```c
while (!should_quit) {
	struct ipcon_msg im;

	/* if no message comes, program will sleep here. */
	ret = ipcon_rcv(handler, &im);
	if (ret < 0) {
		fprintf(stderr, "Receive msg failed: %s(%d)\n",
				strerror(-ret), -ret);
		should_quit = 1;
		continue;
	}


	if (im.type == LIBIPCON_NORMAL_MSG)  {
		char *src_peer = im.peer;

		/* deal with message from peer src_peer */
		printf("Message from %s: %.*s\n", src_peer, im.len, im.buf);
		...
		continue;
	}

	if (im.type == LIBIPCON_GROUP_MSG)  {
		if (!strcmp(im.group, "GroupX")) {
			/* deal with message from group "GroupX" */
			...
			continue;
		}

		if (!strcmp(im.group, "GroupY")) {
			/* deal with message from group "GroupY" */
			...
			continue;
		}

		if (!strcmp(im.group, "GroupZ")) {
			/* deal with message from group "GroupZ" */
			...
			continue;
		}
	}
}
```

Since a message group is identified by a name and often it is a pre-known one
unlike the port number which is decided at run-time, you may find that it is
convenient to just join or leave a group in another thread without the need of
adding logic to enable/disable a specific group control in the message receiving
processing. However, for messages from a peer, you need to manage the peer name
by yourself to distinguish who sends it.

Of course, it is much easier to create multiple peers to deal with different use
case. For example, one for receiving group message, one for service and one for
client ...

### Send a message

We can send messages to either a peer whose name is known or a group
we created. To send a message to a peer, the `ipcon_send_unicast()` API is used.

```c
int ipcon_send_unicast(IPCON_HANDLER handler,
			char *name,
			void *buf,
			size_t size);
```

`handler` is the IPCON handler created by `ipcon_create_handler()`. `name` is the
name of the peer to which we want to send a message. `buf` contains the message 
data to be sent, `size` is the length of message data.

For example, the following code sends a string "Hello world!" to a peer named
"string_service".

**Example: Send messages**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libipcon.h"

#define peer_name	"string_service"
#define str_msg		"Hello world!"

int main (int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;

	handler = ipcon_create_handler("message_sender", LIBIPCON_FLG_DEFAULT);
	if (!handler) {
		fprintf(stderr, "Failed to create handler\n");
		return -1;
	}

	/* Check if the target peer is present */
	if (is_peer_present(handler, peer_name) <= 0) {
		fprintf(stderr, "Peer %s is not present\n", peer_name);
		ipcon_free_handler(handler);
		return -1;
	}

	fprintf(stderr, "Found peer %s\n", peer_name);

	ret = ipcon_send_unicast(handler,
			peer_name,
			str_msg,
			strlen(str_msg) + 1);

	if (ret < 0)
		fprintf(stderr, "Failed to send message to %s: %s (%d)\n",
				peer_name, strerror(-ret), -ret);
	else
		fprintf(stderr, "Message sent successfully to %s\n", peer_name);

	ipcon_free_handler(handler);
	return ret;
}
```

**Note:**
    The maximum data size that IPCON message can transfer is defined in
    `libipcon.h` as `LIBIPCON_MAX_PAYLOAD_LEN` (2048 bytes). This should be
    sufficient for most use cases, but keep in mind that larger messages
    introduce more overhead as the packet may be copied in both the libipcon
    layer and driver layer.

As described above, message sending in IPCON is connectionless - there is no
need for a sender to wait for completion of message reading on the receiver side.

To send a message to a group, the `ipcon_send_multicast()` API is used:

```c
int ipcon_send_multicast(IPCON_HANDLER handler,
			char *name,
			void *buf,
			size_t size,
			int sync);
```

`name` is the group name registered in `ipcon_register_group()`. The `sync` parameter
specifies whether to send synchronously (1) or asynchronously (0). The following
example sends a string "Hello world!" to its "string_group" message group at 1s
intervals.

**Example: Send multicast message**
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "libipcon.h"

#define group_name	"string_group"
#define str_msg		"Hello world!"

int main (int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;

	handler = ipcon_create_handler("provider", LIBIPCON_FLG_DEFAULT);
	if (!handler) {
		fprintf(stderr, "Failed to create handler\n");
		return -1;
	}

	ret = ipcon_register_group(handler, group_name);
	if (ret < 0) {
		fprintf(stderr, "Failed to create group %s: %s (%d)\n", 
			group_name, strerror(-ret), -ret);
		return ret;
	}

	fprintf(stderr, "Group %s is created\n", group_name);

	while (1) {
		ret = ipcon_send_multicast(handler,
				group_name,
				str_msg,
				strlen(str_msg) + 1,
				1);  /* synchronous send */

		if (ret < 0) {
			fprintf(stderr, "Failed to send group message to %s: %s (%d)\n",
				group_name, strerror(-ret), -ret);
			break;
		}

		printf("Sent message to group %s\n", group_name);
		usleep(1000 * 1000);  /* Wait 1 second */
	}

	ipcon_free_handler(handler);
	return ret;
}
```

**Note:**
    A multicast message sender will not care about whether the messages are
    received by all subscribers or not. It even does not care about whether
    there are any subscribers or not.

### IPCON_KERNEL_GROUP message group

When the IPCON driver is loaded, it will register a special IPCON_KERNEL_GROUP
(named "ipcon_kevent") message group to send some service/group
register/unregister events. The message format of this message group is as
follows:

```c
struct ipcon_kevent {
	enum ipcon_kevent_type type;
	union {
		struct {
			char name[IPCON_MAX_SRV_NAME_LEN];
			__u32 portid;
		} srv;
		struct {
			char name[IPCON_MAX_GRP_NAME_LEN];
			__u32 groupid;
		} grp;
		struct {
			__u32 portid;
		} peer;
	};
};
```

- `type`
  The type of the event, which is defined as:

  ```c
	enum ipcon_kevent_type {
		IPCON_EVENT_SRV_ADD,
		IPCON_EVENT_SRV_REMOVE,
		IPCON_EVENT_GRP_ADD,
		IPCON_EVENT_GRP_REMOVE,
		IPCON_EVENT_PEER_REMOVE,
	};
  ```

  - `IPCON_EVENT_SRV_ADD` - A service is registered.
  - `IPCON_EVENT_SRV_REMOVE` - A service is unregistered.
  - `IPCON_EVENT_GRP_ADD` - A user message group is registered.
  - `IPCON_EVENT_GRP_REMOVE` - A user message group is unregistered.
  - `IPCON_EVENT_PEER_REMOVE` - A peer is removed.

- `srv`
  The service information only valid when type is `IPCON_EVENT_SRV_ADD` or
  `IPCON_EVENT_SRV_REMOVE`. `name` describes the name of the service and the
  `portid` is the port number of the service peer.

- `grp`
  The group information only valid when type is `IPCON_EVENT_GRP_ADD` or
  `IPCON_EVENT_GRP_REMOVE`. `name` describes the name of the group and the
  `groupid` describe the internal group id (not visible to user, maybe removed
  in the future.)

- `peer`
  The peer information only valid when type is `IPCON_EVENT_PEER_REMOVE`. `portid`
  describes the port number of the peer that is removed.

By using the IPCON_KERNEL_GROUP message, we can detect the service/group dynamically.
Here is an example to dynamically detect "ServerX" service and communicate with it.

**Example: Use IPCON_KERNEL_GROUP message group to detect a service.**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libipcon.h>

#define service_name	"ServerX"
__u32 srv_port;

int main (int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER	handler;

	handler = ipcon_create_handler();
	if (!handler) {
		fprintf(stderr, "Failed to create handler\n");
		return -1;
	}

	/*
	 * 1. Join the ipcon_kevent group
	 *
	 *    IPCON_KERNEL_GROUP here is defined as "ipcon_kevent" in ipcon.h,
	 *    you should use this macro and avoid using "ipcon_kevent" directly.
	 */
	ret = ipcon_join_group(handler, IPCON_KERNEL_GROUP, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to join %s group.\n",
			IPCON_KERNEL_GROUP);

		ipcon_free_handler(handler);
		return ret;
	}

	/*
	 * 2. Find "ServerX" service, it maybe failed.
	 *
	 *    Note: this step 2 must NOT be done before step 1 above.
	 *          Otherwise you may failed to detect service properly.
	 */
	ipcon_find_service(handler, service_name, &srv_port);

	while (!should_quit) {
		struct ipcon_msg im;
		struct ipcon_kevent *ik = NULL;

		ret = ipcon_rcv(handler, &im);
		if (ret < 0) {
			fprintf(stderr, "Receive msg failed: %s(%d)\n",
					strerror(-ret), -ret);
			should_quit = 1;
			continue;
		}

		if (im.type == IPCON_GROUP_MSG)  {
			if (!strcmp(im.group, IPCON_KERNEL_GROUP)) {
				ik = (struct ipcon_kevent *)im.buf;

				if ((ik.type = IPCON_EVENT_SRV_ADD) &&
					!srv_port) {

					/*
					 * 3. "ServerX" service is added.
					 *     Get its port number and start
					 *     communicating to it.
					 */
					if (!strcmp(ik.srv.name, service_name)) {
						srv_port = ik.srv.portid;
						send_hello_msg_to_srv_port();
						...
						continue;
					}

				}

				if ((ik.type = IPCON_EVENT_SRV_REMOVE) &&
					srv_port) {

					/*
					 * 5. "ServerX" service is unregisterred
					 *    Service peer has stopped publishing
					 *    its name, port number can still be
					 *    used to communicate with it.
					 */
					if (!strcmp(ik.srv.name, service_name))
						i_know_but_i_do_not_care();

					continue;
				}

				if ((ik.type = IPCON_EVENT_PEER_REMOVE) &&
					srv_port) {

					/*
					 * 6. Peer of original "ServiceX" is removed
					 *    We can not communicate to it anymore
					 *    ...
					 */

					if (im.peer.portid == srv_port)
						srv_port = 0;
					...

					continue;
				}
			}

			...

			continue;
		}

		if  (im.type == IPCON_NORMAL_MSG) {
			if (im.port == srv_port) {
				/*
				 * 4. Process the message from service "ServerX"
				 *    peer.
				 */
				 process_msg_from_srv_port();
			}

			...
		}
	}


	ipcon_free_handler(handler);

	return ret;
}
```

Recall that the port number of a user process peer will never be 0, the example
above uses `srv_port == 0` to judge service "ServerX" is added or removed.
Attention should be paid here that in order to detect the service properly, the
order of step 1 and 2 must NOT be reversed. Otherwise if "ServerX" is
registered between these two calls, you will fail to detect it.

## Conclusion

IPCON is designed as a convenience mechanism for packet-based IPC on Linux. I have
tried to describe the content as correctly as possible to reflect the design and
present implementation of it. There may be mistakes. Any comments, advice or
bug reports are very much appreciated.

## Appendix

### Samples

Some samples can be found in the "samples" directory of the source package.

- **ipcon_server.c**
  A "server" which register a "ipcon_server" service and a "str_msg" group.
  Any string message sent to it will be forwarded to "str_msg" message group.

- **ipcon_user.c**
  A "subscriber" who subscribes the "str_msg" message group provided by
  ipcon_server and output the message received from this group.

- **ipcon_sender.c**
  A message sender who gets the port number of ipcon_server by resolving the service
  name "ipcon_server" and sends the specified message (passed as parameter
  argv[1]) to "ipcon_server" at 1s interval.

- **ipcon_cmd.c**
  Same as ipcon_sender but is a one-shot message sender.