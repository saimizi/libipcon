AC_PREREQ([2.65])
AC_INIT([ipcon],1.0.0)
AM_INIT_AUTOMAKE([foreign])

LT_PREREQ([2.2])
LT_INIT


AC_CONFIG_MACRO_DIRS([m4])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AM_SILENT_RULES([yes])
: ${CFLAGS=""}
: ${CXXFLAGS=""}

AC_PROG_CC
AC_PROG_CXX

PKG_CHECK_MODULES([LIBNL_GENL], [libnl-genl-3.0])

LIBNL_GENL_VER="`pkg-config --modversion libnl-genl-3.0`"
MIN_LIBNL_GENL_VER="3.2.27"
AC_MSG_CHECKING([if libnl-genl version  $LIBNL_GENL_VER >= $MIN_LIBNL_GENL_VER])

AX_COMPARE_VERSION( [$LIBNL_GENL_VER],
		    [ge],
		    [$MIN_LIBNL_GENL_VER],
		    [AC_MSG_RESULT([yes])],
		    [AC_MSG_ERROR([version is too old.], [1])]
		  )
AC_ARG_WITH([ksrc],
	AS_HELP_STRING([--with-ksrc],[Linux kernel path.]))

AS_IF([test "x$with_ksrc" != "x"],
	[ksrc=$with_ksrc],
	[ksrc="/lib/modules/`uname -r`/build"])

AC_SUBST(ksrc)
AC_CONFIG_FILES([Makefile
		 driver/Makefile
		 lib/Makefile
		 test/Makefile
		])
AC_OUTPUT

echo \
"-------------------------------------------------

${PACKAGE_NAME} Version ${PACKAGE_VERSION}

Prefix: '${prefix}'.
Compiler: '${CC} ${CFLAGS} ${CPPFLAGS}'

Package features:
	kernel src: ${ksrc}

-------------------------------------------------"
