# Benchmarks

This directory contains benchmarks of various JWT parsers.

## Libraries

* [jwtd](https://code.dlang.org/packages/jwtd) - most used dlang JWT lib
* [fastjwt](https://code.dlang.org/packages/fastjwt) - alternative with much less GC usage, but phobos only
* [libjwt](https://github.com/benmcollins/libjwt)  - most liked C library on [jwt.io](https://jwt.io) to have some comparison with other languages
* [l8w8jwt](https://github.com/GlitchedPolygons/l8w8jwt) - another neat C library that uses [MbedTLS](https://tls.mbed.org/) instead of OpenSSL

There are other D libraries like:

* [jwt](https://code.dlang.org/packages/jwt) - repository is archived and it's slower than jwtd
* [hunt-jwt](https://code.dlang.org/packages/hunt-jwt) - alpha stage, seems to be heavily inspired by jwt

## How to run it yourself

Tests can be run in a docker container.

* prepare the environment - `make container`
* enter it's shell - `make shell`
* execute benchmark - `make`

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

For comparison `openssl speed rsa ecdsa` yelds:

|                               |      sign/s  | verify/s     |
|:-----------------------------:| ------------:| ------------:|
| rsa  512 bits                 |      31980.1 |     503865.1 |
| rsa 1024 bits                 |      13879.7 |     215286.4 |
| **rsa 2048 bits**             |   **1985.4** |  **68151.8** |
| rsa 3072 bits                 |        657.7 |      33044.4 |
| rsa 4096 bits                 |        291.2 |      19187.2 |
| rsa 7680 bits                 |         31.2 |       5608.5 |
| rsa 15360 bits                |          6.2 |       1413.4 |
| 224 bits ecdsa (nistp224)     |      22521.1 |       9850.9 |
| **256 bits ecdsa (nistp256)** |  **56027.8** |  **17849.5** |
| 384 bits ecdsa (nistp384)     |       1305.7 |       1597.5 |
| 521 bits ecdsa (nistp521)     |       4317.5 |       2177.1 |

**Note:** jwtd and libjwt are parsing the header/payload to JSON and so comparison is not completely fair. They have no api to return just the base64 decoded payload as with fastjwt and jwtlited.

**Note:** jwtlited benchmark uses static array as a buffer to decode payload or encode token to. That itself makes about 15% difference. Libjwt can output only to self allocated string or file so it allocates in each step. Faastjwt uses `StringBuffer` and can't use other sink type. Jwtd decodes to JSONValue and encodes to `string`.

### Binary size

All benchmark binaries consists pretty much with the same dlang boilerplate (even C library one).

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/sizes.png)

### HMAC HS256 signature

#### Performance

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/speed_hs256.png)

|     | fastjwt | jwtd botan | jwtd openssl | jwtd phobos | jwtlited gnutls | jwtlited openssl | jwtlited phobos | l8w8jwt | libjwt |
|:---:| -------:| ----------:| ------------:| -----------:| ---------------:| ----------------:| ---------------:| -------:| ------:|
| val |  196772 |      93861 |       486854 |      169319 |         2040816 |          2369668 |          205676 |  394944 | 266240 |
| dec |  200803 |      82304 |       292226 |      136836 |         1805054 |          2066115 |          203500 |  388500 | 172950 |
| enc |  173310 |      91793 |       460829 |      168293 |         1923076 |          2136752 |          201857 |  131027 | 216076 |

#### GC memory used

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/gcusage_hs256.png)

|     | fastjwt | jwtd botan | jwtd openssl | jwtd phobos | jwtlited gnutls | jwtlited openssl | jwtlited phobos | l8w8jwt | libjwt |
|:---:| -------:| ----------:| ------------:| -----------:| ---------------:| ----------------:| ---------------:| -------:| ------:|
| val | 22.8882 |    526.429 |      419.617 |     419.617 |               0 |                0 |               0 |       0 |      0 |
| dec | 22.8882 |    946.046 |      839.234 |     839.234 |               0 |                0 |               0 |       0 |      0 |
| enc | 22.8889 |    595.099 |      488.287 |     488.287 |               0 |                0 |               0 |       0 |      0 |

### RSA RS256 signature

#### Performance

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/speed_rs256.png)

|     | jwtd openssl | jwtlited gnutls | jwtlited openssl | l8w8jwt | libjwt |
|:---:| ------------:| ---------------:| ----------------:| -------:| ------:|
| val |        32383 |           40849 |            58275 |   15757 |  31766 |
| dec |        31269 |           40387 |            59665 |   15649 |  29922 |
| enc |         1133 |             723 |             1924 |     379 |   1133 |

### ECDSA ES256 signature

#### Performance

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/speed_es256.png)

|     | jwtlited gnutls | jwtlited openssl | l8w8jwt | libjwt |
|:---:| ---------------:| ----------------:| -------:| ------:|
| val |            6182 |            17283 |     474 |  12272 |
| dec |            6140 |            17464 |     472 |  11893 |
| enc |           17001 |            49067 |     927 |  22114 |
