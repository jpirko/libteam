MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

html-local:
if HAVE_DOXYGEN
	$(DOXYGEN) Doxyfile
endif

clean-local:
	rm -rf api
