lib_LTLIBRARIES = libipcon.la
include_HEADERS = ${srcdir}/libipcon.h ${top_srcdir}/driver/ipcon.h

libipcon_la_CPPFLAGS =	-g -Wextra \
			-Werror \
			-Wformat=2 \
			-Wcast-qual \
			-Wcast-align \
			-Wconversion \
			-Wfloat-equal \
			-Wpointer-arith \
			-Wswitch-enum \
			-Wno-unused-function \
			-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
			-ftrapv \
			-fstack-protector \
			-rdynamic \
			-funwind-tables \
			-I ${top_srcdir}/driver \
			$(LIBNL_GENL_CFLAGS)

libipcon_la_SOURCES = libipcon.c util.c
libipcon_la_LIBADD = -lpthread $(LIBNL_GENL_LIBS)
libipcon_la_LDFLAGS = -Wl,--version-script,${srcdir}/ipcon.map -version-info 0:0:0
