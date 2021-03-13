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

## Tests

Tests are controled by the `runner.d` script, that generates token and passes it as a command argument with additional parameters as:

* type of test `val`, `dec`, `enc` - see below
* cycle count - how many times should be the selected operation performed by the library
* algorithm - selected algorithm to work with, ie `HS256`
* token or payload to work with
* secret or signature to use to validate or encode the token

Each compiled benchmark executes the operation with the provided parameters and if all passes returns 0 and on `stdout` these lines are expected:

* text result of the operation
* total number of milliseconds the benchmark loop takes
* GC used bytes during the test (measured as a difference of [GC.allocatedInCurrentThread](https://dlang.org/phobos/core_memory.html#.GC.allocatedInCurrentThread))

### val

This test performs only validation of the signature if the used library allows it.
It doesn't work or validate content of the payload, only header, generic JWT format and it's signature against header/payload.

Expected result is `true`.

### dec

This extends the validation to that it requires decoding of the payload from base64.

Expected result is the raw payload JSON.

### enc

This encodes the token using provided payload and returns it in the expected result. `runner.d` checks it's validity and compares the payload with the original one.

**Note:** jwtd and fastjwt accepts only Json structure, jwtlited and libjwt can write provided string payload directly (so just a base64 encode).

## Results

**Tested on:**

* **CPU** - AMD Ryzen 7 3700X 8-Core Processor
* **OS** - Fedora 32

**Note:** jwtd supports phobos, openssl and botan variants. All are added to this benchmark, but botan variant is really slow and others differences aren't visible that much on the charts, so I've commented it out in the makefile.

**Note:** jwtd and libjwt are parsing the header/payload to JSON and so comparison is not completely fair. They have no api to return just the base64 decoded payload as with fastjwt and jwtlited.

**Note:** jwtlited benchmark uses static array as a buffer to decode payload or encode token to. That itself makes about 15% difference. Libjwt can output only to self allocated string or file so it allocates in each step. Faastjwt uses `StringBuffer` and can't use other sink type. Jwtd decodes to JSONValue and encodes to `string`.

### Binary size

All benchmark binaries consists pretty much with the same dlang boilerplate (even C library one).

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/sizes.png)

### HMAC HS256 signature

#### Performance

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/speed.png)

#### GC memory used

`jwtlited` is not visible there as it doesn't allocate anything on GC.

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/gcusage.png)
