bin_PROGRAMS = ipcon_test

common_cflags = -g -O2 -Wall \
		-I ${top_builddir}/driver/ \
		-I ${top_builddir}/lib/ \
		$(LIBNL_GENL_CFLAGS)

common_ldflags =$(LIBNL_GENL_LIBS)

ipcon_test_SOURCES = ipcon_test.c
ipcon_test_CFLAGS =$(common_cflags)
#ipcon_test_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_test_LDADD = $(common_ldflags)


AM_CFLAGS = -g -O2 -Wall
