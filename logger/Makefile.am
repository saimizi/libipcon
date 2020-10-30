bin_PROGRAMS = ipcon_cmd ipcon_logger

common_cflags = -g -O2 -Wall \
		-I ${top_srcdir}/driver/ \
		-I ${top_srcdir}/lib/ \
		-rdynamic \
		-funwind-tables \
		$(LIBNL_GENL_CFLAGS)

common_ldflags =$(LIBNL_GENL_LIBS)

include_HEADERS = ${srcdir}/ipcon_logger.h

ipcon_cmd_SOURCES = ipcon_cmd.c
ipcon_cmd_CFLAGS =$(common_cflags)
ipcon_cmd_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_cmd_LDADD = $(common_ldflags) -lipcon

ipcon_logger_SOURCES = ipcon_logger.c
ipcon_logger_CFLAGS =$(common_cflags)
ipcon_logger_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_logger_LDADD = $(common_ldflags) -lipcon

AM_CFLAGS = -g -O2 -Wall
