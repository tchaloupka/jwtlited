DC = ldc2
DFLAGS += -release -O3 -boundscheck=off -ffast-math -mcpu=native
docker_build = docker build . -t jwtbench

.PHONY: all
all: build
	./runner.d

.PHONY: build
build:
	DFLAGS=$(DLFAGS) dub build --single b_fastjwt.d --compiler=$(DC)
	DFLAGS=$(DLFAGS) dub build --single b_jwtd.d -c openssl --compiler=$(DC)
	DFLAGS=$(DLFAGS) dub build --single b_jwtd.d -c phobos --compiler=$(DC)
	# DFLAGS=$(DLFAGS) dub build --single b_jwtd.d -c botan --compiler=$(DC)
	DFLAGS=$(DLFAGS) dub build --single b_jwtlited.d -c openssl --compiler=$(DC)
	DFLAGS=$(DLFAGS) dub build --single b_libjwt.d --compiler=$(DC)

.PHONY: clean
clean:
	rm -f bench_*
	rm -rf .dub

.PHONY: container
container:
	$(docker_build)

.PHONY: rebuildcontainer
rebuild:
	$(docker_build) --no-cache

.PHONY: shell
shell:
	docker run -it --rm -v $(shell pwd)/..:/src:Z --network="host" jwtbench
