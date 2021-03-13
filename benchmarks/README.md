# Benchmarks

This directory contains benchmarks of various JWT parsers.

## Libraries

* [jwtd](https://code.dlang.org/packages/jwtd) - most used dlang JWT lib
* [fastjwt](https://code.dlang.org/packages/fastjwt) - alternative with much less GC usage, but phobos only
* [libjwt](https://github.com/benmcollins/libjwt)  - most liked C library on [jwt.io](https://jwt.io) to have some comparison with other languages

There are others like:

* [jwt](https://code.dlang.org/packages/jwt) - repository is archived and it's slower than jwtd
* [hunt-jwt](https://code.dlang.org/packages/hunt-jwt) - alpha stage, seems to be heavily inspired by jwt

## How to run it yourself

LDC compiler is required, then just enter this directory and hit `make`.

It generates some textual output with the values and charts in results subfolder.

## Results

**Note:** jwtd supports phobos, openssl and botan variants. All are added to this benchmark, but botan variant is really slow and others differences aren't visible that much on the charts, so I've commented it out in the makefile.

**Note:** jwtd and libjwt are parsing the header/payload to JSON and so comparison is not completely fair. They have no api to return just the base64 decoded payload as with fastjwt and jwtlited.

### Binary size

All benchmark binaries consists pretty much with the same dlang boilerplate (even C library one).

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/sizes.png)

### HMAC HS256 signature

#### Performance

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/speed.png)

#### GC memory used

This represents the memory allocated during the test (determined by [GC.allocatedInCurrentThread](https://dlang.org/phobos/core_memory.html#.GC.allocatedInCurrentThread).

`jwtlited` is not visible there as it doesn't allocate anything on GC.

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/gcusage.png)
