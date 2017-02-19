bin_PROGRAMS = ipcon_server ipcon_sender ipcon_user ipcon_cmd

common_cflags = -g -O2 -Wall \
		-I ${top_builddir}/driver/ \
		-I ${top_builddir}/lib/ \
		$(LIBNL_GENL_CFLAGS)

common_ldflags =$(LIBNL_GENL_LIBS)

ipcon_test_SOURCES = ipcon_test.c
ipcon_test_CFLAGS =$(common_cflags)
#ipcon_test_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_test_LDADD = $(common_ldflags)

ipcon_server_SOURCES = ipcon_server.c
ipcon_server_CFLAGS =$(common_cflags)
ipcon_server_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_server_LDADD = $(common_ldflags) -lipcon

ipcon_sender_SOURCES = ipcon_sender.c
ipcon_sender_CFLAGS =$(common_cflags)
ipcon_sender_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_sender_LDADD = $(common_ldflags) -lipcon

ipcon_user_SOURCES = ipcon_user.c
ipcon_user_CFLAGS =$(common_cflags)
ipcon_user_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_user_LDADD = $(common_ldflags) -lipcon

ipcon_cmd_SOURCES = ipcon_cmd.c
ipcon_cmd_CFLAGS =$(common_cflags)
ipcon_cmd_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_cmd_LDADD = $(common_ldflags) -lipcon

AM_CFLAGS = -g -O2 -Wall
