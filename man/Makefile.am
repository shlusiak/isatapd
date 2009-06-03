EXTRA_DIST = isatapd.man
DISTCLEANFILES = isatapd.8 isatapd.8.html

man_MANS = isatapd.8

all: isatapd.8
html: isatapd.8.html

MAN_SUBSTS = \
	-e 's|__version__|"$(PACKAGE)-$(VERSION)"|'

isatapd.8: isatapd.man
	sed $(MAN_SUBSTS) < $< > $@

isatapd.8.html: isatapd.8
	man2html isatapd.8 > isatapd.8.html

clean:
	rm -f isatapd.8 isatapd.8.html
