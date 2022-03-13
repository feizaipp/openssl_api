#! /bin/sh
touch NEWS README ChangeLog AUTHORS
aclocal
autoconf
autoheader
libtoolize --copy --force
automake --add-missing
