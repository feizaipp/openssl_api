#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(rpm-multi, 1.0)
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS(config.h)
LT_INIT([disable-static])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.31.13])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(GIO, [gio-unix-2.0 >= 2.31.13])
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)

# Checks for libraries.
PKG_CHECK_MODULES(DBUS_GLIB, dbus-glib-1, have_dbus_glib=yes, have_dbus_glib=no)
if test x$have_dbus_glib = xno ; then
    AC_MSG_ERROR([DBus-GLib development libraries not found])
fi

AM_CONDITIONAL(HAVE_DBUS_GLIB, test x$have_dbus_glib = xyes)

AC_SUBST(DBUS_GLIB_CFLAGS)
AC_SUBST(DBUS_GLIB_LIBS)

PKG_CHECK_MODULES(SQLITE3, sqlite3, have_sqlite3=yes, have_sqlite3=no)
if test x$have_sqlite3 = xno ; then
    AC_MSG_ERROR([SQLITE3 development libraries not found])
fi

AM_CONDITIONAL(HAVE_SQLITE3, test x$have_sqlite3 = xyes)

AC_SUBST(SQLITE3_CFLAGS)
AC_SUBST(SQLITE3_LIBS)

PKG_CHECK_MODULES(CRYPTO, libcrypto, have_crypto=yes, have_cryptol=no)
if test x$have_crypto = xno ; then
    AC_MSG_ERROR([CRYPTO development libraries not found])
fi

AC_SUBST(CRYPTO_CFLAGS)
AC_SUBST(CRYPTO_LIBS)

PKG_CHECK_MODULES(JINSHI, libjinshi, have_jinshi=yes, have_jinshi=no)
if test x$have_jinshi = xno ; then
    AC_MSG_ERROR([JINSHI development libraries not found])
fi

AC_SUBST(JINSHI_CFLAGS)
AC_SUBST(JINSHI_LIBS)

# systemd
AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
            [],
            [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
if test "x$with_systemdsystemunitdir" != "xno"; then
  AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
fi
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$systemdsystemunitdir"])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT([Makefile
lib/Makefile
src/Makefile
data/Makefile
tools/Makefile])

echo "
               rpm-multi $VERSION
             ================

        prefix:                     ${prefix}
        libdir:                     ${libdir}
        libexecdir:                 ${libexecdir}
        bindir:                     ${bindir}
        sbindir:                    ${sbindir}
        datadir:                    ${datadir}
        sysconfdir:                 ${sysconfdir}
        localstatedir:              ${localstatedir}
        docdir:                     ${docdir}
        introspection:              ${found_introspection}

        udevdir:                    ${udevdir}
        systemdsystemunitdir:       ${systemdsystemunitdir}
        using libsystemd-login:     ${have_libsystemd_login}
        using libelogind:           ${have_libelogind}
        use /media for mounting:    ${fhs_media}
        acl support:                ${have_acl}
        libblockdev_part support:   ${have_libblockdev_part}

        compiler:                   ${CC}
        cflags:                     ${CFLAGS}
        cppflags:                   ${CPPFLAGS}

        Maintainer mode:            ${USE_MAINTAINER_MODE}
        Building api docs:          ${enable_gtk_doc}
        Building man pages:         ${enable_man}

        Enable modules:             ${enable_modules_info}

        BTRFS module:               ${have_btrfs}
        iSCSI module:               ${have_iscsi}${have_libiscsi_session_info_msg}
        LVM2  module:               ${have_lvm2}
        LVMCache:                   ${have_lvmcache}
        Zram module:                ${have_zram}
        LibStorageMgmt module:      ${have_lsm}
        Bcache module:              ${have_bcache}
"
