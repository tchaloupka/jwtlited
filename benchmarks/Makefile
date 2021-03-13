DC = ldc2
DFLAGS += -release -O3 -boundscheck=off -ffast-math -mcpu=native

.PHONY: all
all: build
	./runner.d

.PHONY: build
build: .dub/packages/fastjwt-1.1.1 .extern/libs/libjwt.a
	DFLAGS=$(DLFAGS) dub build --single fastjwt.d --compiler=$(DC)
	DFLAGS=$(DLFAGS) dub build --single jwtd_openssl.d --compiler=$(DC)
	DFLAGS=$(DLFAGS) dub build --single jwtd_phobos.d --compiler=$(DC)
	# DFLAGS=$(DLFAGS) dub build --single jwtd_botan.d --compiler=$(DC)
	DFLAGS=$(DLFAGS) dub build --single jwtlited_openssl.d --compiler=$(DC)
	DFLAGS="$(DLFAGS) -L=-L.extern/libs" dub build --single libjwt.d --compiler=$(DC)

.dub/packages/fastjwt-1.1.1:
	dub fetch fastjwt@1.1.1 --cache=local
	sed -i "s/Base64.decode/Base64URLNoPadding.decode/g" .dub/packages/fastjwt-1.1.1/fastjwt/source/fastjwt/jwt.d

.extern/libs/libjansson.a: .extern/jansson
	mkdir -p .extern/libs
	cd .extern/jansson && autoreconf -i && ./configure && make
	cp .extern/jansson/src/.libs/libjansson.a .extern/libs/
	strip -g .extern/libs/libjansson.a

.extern/libs/libjwt.a: .extern/libjwt .extern/libs/libjansson.a
	cd .extern/libjwt && autoreconf -i && JANSSON_LIBS=-L../../libs JANSSON_CFLAGS=-I../../jansson/src ./configure
	sed -i '/SUBDIRS = .*/c\SUBDIRS = include libjwt' .extern/libjwt/Makefile
	cd .extern/libjwt && make
	cp .extern/libjwt/libjwt/.libs/libjwt.a .extern/libs/
	strip -g .extern/libs/libjwt.a

.extern/jansson:
	mkdir -p .extern
	cd .extern && git clone git@github.com:akheron/jansson.git

.extern/libjwt:
	mkdir -p .extern
	cd .extern && git clone git@github.com:benmcollins/libjwt.git

.PHONY: clean
clean:
	rm -f bench_*
	rm -rf .dub
	rm -rf .extern
