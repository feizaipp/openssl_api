AM_CPPFLAGS = \
	$(DBUS_GLIB_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GIO_CFLAGS) \
	$(SQLITE3_CFLAGS) \
	$(JINSHI_CFLAGS)

LIBS = \
	$(DBUS_GLIB_LIBS) \
	$(GLIB_LIBS) \
	$(GIO_LIBS) \
	$(SQLITE3_LIBS) \
	$(JINSHI_LIBS) \
	-ljinshikey


dbus_built_sources = rpmmulti-generated.h rpmmulti-generated.c

$(dbus_built_sources) : $(top_srcdir)/data/org.freedesktop.RpmMultiService.xml
	gdbus-codegen --interface-prefix org.freedesktop.RpmMultiService --c-namespace RpmMulti --generate-c-code=rpmmulti-generated $<

BUILT_SOURCES =										\
	$(dbus_built_sources)								\
	$(NULL)

rpmmultilibdir = $(libdir)
rpmmultilib_LTLIBRARIES = librpmmulti.la
librpmmulti_la_SOURCES = sm2.c sm3.c sqlite_helper.c utils.c callback.c api.c ukey.c $(BUILT_SOURCES)
librpmmulti_la_LIBADD = -L/usr/local/jinshi-gmssl/lib -lcrypto
librpmmulti_la_CFLAGS = -I/usr/local/jinshi-gmssl/include
