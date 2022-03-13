AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GIO_CFLAGS)

LIBS = \
	$(GLIB_LIBS) \
	$(GIO_LIBS)

rpmmultiserviceprivdir = $(libexecdir)/rpmmultiservice
rpmmultiservicepriv_PROGRAMS = rpmmultiserviced
rpmmultiserviced_SOURCES = main.c
rpmmultiserviced_LDADD = $(top_srcdir)/lib/librpmmulti.la

CLEANFILES = $(BUILT_SOURCES)

