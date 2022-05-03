#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([sm2-EVP], [1.0], [soveazhang@gmail.com])
AM_INIT_AUTOMAKE(sm2-EVP, 1.0)
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.11 dist-xz no-dist-gzip tar-ustar foreign subdir-objects -Wall -Werror])
AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LIBTOOL
# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([crypto], [main])

# Checks for header files.
AC_CHECK_HEADERS([string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 src/c/Makefile
                 src/cpp/Makefile])
AC_OUTPUT

dnl ==========================================================================
AC_MSG_NOTICE([

        sm2-EVP $VERSION
        ==============

        prefix:                   ${prefix}
        C compiler:               ${CC}
        C++ compiler:             ${CXX}

        Now type 'make' to build $PACKAGE
])
