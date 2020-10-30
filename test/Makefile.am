bin_PROGRAMS = ipcon_server ipcon_sender ipcon_user ipcon_server_poll ipcon_kevent

common_cflags = -g -O2 -Wall \
		-I ${top_srcdir}/driver/ \
		-I ${top_srcdir}/lib/ \
		-I ${top_srcdir}/logger/ \
		-rdynamic \
		-funwind-tables \
		$(LIBNL_GENL_CFLAGS)

common_ldflags =$(LIBNL_GENL_LIBS)

ipcon_server_SOURCES = ipcon_server.c
ipcon_server_CFLAGS =$(common_cflags)
ipcon_server_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_server_LDADD = $(common_ldflags) -lipcon -ljslist

ipcon_sender_SOURCES = ipcon_sender.c
ipcon_sender_CFLAGS =$(common_cflags)
ipcon_sender_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_sender_LDADD = $(common_ldflags) -lipcon

ipcon_user_SOURCES = ipcon_user.c
ipcon_user_CFLAGS =$(common_cflags)
ipcon_user_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_user_LDADD = $(common_ldflags) -lipcon

ipcon_server_poll_SOURCES = ipcon_server_poll.c
ipcon_server_poll_CFLAGS =$(common_cflags)
ipcon_server_poll_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_server_poll_LDADD = $(common_ldflags) -lipcon

ipcon_kevent_SOURCES = ipcon_kevent.c
ipcon_kevent_CFLAGS =$(common_cflags)
ipcon_kevent_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_kevent_LDADD = $(common_ldflags) -lipcon

AM_CFLAGS = -g -O2 -Wall
