DC = ldc2
DFLAGS += -release -O3 -boundscheck=off -ffast-math -mcpu=native

.PHONY: all
all: build
	./runner.d

.PHONY: build
build:
	DFLAGS=$(DLFAGS) dub build --single jwtd_openssl.d --compiler=$(DC)
	DFLAGS=$(DLFAGS) dub build --single jwtd_phobos.d --compiler=$(DC)
	DFLAGS=$(DLFAGS) dub build --single jwtd_botan.d --compiler=$(DC)

.PHONY: clean
clean:
	rm -f bench_*
	rm *.png
	rm -rf .dub
