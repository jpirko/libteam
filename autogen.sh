#!/bin/bash

if [ ! -d "m4" ]; then
	mkdir m4
fi
autoreconf -fi;
rm -Rf autom4te.cache;
