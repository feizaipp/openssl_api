
NULL =

dbusservicedir       = $(datadir)/dbus-1/system-services
dbusservice_in_files = org.freedesktop.RpmMultiService.service.in
dbusservice_DATA     = $(dbusservice_in_files:.service.in=.service)

$(dbusservice_DATA): $(dbusservice_in_files) Makefile
	@sed -e "s|\@rpmmultiserviceprivdir\@|$(libexecdir)/rpmmultiservice|" $< > $@

dbusconfdir = $(sysconfdir)/dbus-1/system.d
dbusconf_in_files = org.freedesktop.RpmMultiService.conf.in
dbusconf_DATA = $(dbusconf_in_files:.conf.in=.conf)

$(dbusconf_DATA): $(dbusconf_in_files) Makefile
	cp $< $@

pkgconfdir = /usr/lib64/pkgconfig
pkgconf_in_files = rpmmulti.pc.in
pkgconf_DATA = $(pkgconf_in_files:.pc.in=.pc)

$(pkgconf_DATA): $(pkgconf_in_files) Makefile
	cp $< $@

rpmmulticonfdir = /etc
rpmmulticonf_in_files = rpm.config.in
rpmmulticonf_DATA = $(rpmmulticonf_in_files:.config.in=.config)

$(rpmmulticonf_DATA): $(rpmmulticonf_in_files) Makefile
	cp $< $@

systemdservice_in_files = rpmmultiservice.service.in
if HAVE_SYSTEMD
systemdservicedir       = $(systemdsystemunitdir)
systemdservice_DATA     = $(systemdservice_in_files:.service.in=.service)

$(systemdservice_DATA): rpmmultiservice.service.in Makefile
	@sed -e "s|\@rpmmultiserviceprivdir\@|$(libexecdir)/rpmmultiservice|" rpmmultiservice.service.in > rpmmultiservice.service
endif


EXTRA_DIST =                                                                   \
	org.freedesktop.RpmMultiService.xml                                            \
	$(systemdservice_in_files)                                             \
	$(dbusservice_in_files)                                                \
	$(dbusconf_in_files)                                                   \
	$(NULL)

clean-local:
	rm -f *~                                                               \
	$(dbusservice_DATA)                                                    \
	$(dbusconf_DATA)                                                       \
	$(systemdservice_DATA)
