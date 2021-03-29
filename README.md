# jwtlited
[![Actions Status](https://github.com/tchaloupka/jwtlited/workflows/ci/badge.svg)](https://github.com/tchaloupka/jwtlited/actions)
[![Latest version](https://img.shields.io/dub/v/jwtlited.svg)](https://code.dlang.org/packages/jwtlited)
[![Dub downloads](https://img.shields.io/dub/dt/jwtlited.svg)](http://code.dlang.org/packages/jwtlited)
[![codecov](https://codecov.io/gh/tchaloupka/jwtlited/branch/main/graph/badge.svg)](https://codecov.io/gh/tchaloupka/jwtlited)
[![license](https://img.shields.io/github/license/tchaloupka/jwtlited.svg)](https://github.com/tchaloupka/jwtlited/blob/main/LICENSE)

Fast and lightweight [dlang](https://dlang.org) library to handle [JWT](https://jwt.io) tokens.

It's splitted to multiple submodules to fulfill the needs without forcing unused dependencies.

Some of these should be supported in `betterC`, but this is a WIP.

It doesn't force any JSON parser/serializer dependency, but tries to do least operations possible on itself.

For example if one needs to just validate the signature, it decodes and checks algorithm in the header, decodes the signature and check it. It doesn't touch the payload part.

When decoding, payload is still optional to be base64 decoded (based on the provided sink).

Currently payload content is not checked at all (ie for `exp` claim). One needs to call decode with payload sink and check it's contents manualy in a desired way and using whatever JSON parser.

I'd like to add payload validator for known claims too, but again it's a WIP.

Similarly when encoding, currently it's needed that raw, already json serialized payload, is passed to `encode` function.

Main API consists of just these methods:

```
bool decode(V, T, HS, PS)(auto ref V validator, T token, auto ref HS headSink, auto ref PS payloadSink);
bool decode(V, T, S)(auto ref V validator, T token, auto ref S payloadSink);
bool validate(V, T)(auto ref V validator, T token);
int encode(S, O, P)(auto ref S signer, auto ref O output, P payload);
```

So basically one just initialize required algorithm with a secret key and then passes it to these functions with possible sinks to store results.
This way, one can provide his own algorithms handlers.

To use the library, just add for example this to your `dub.sdl`:

```SDL
dependency "jwtlited:openssl" version=">=1.0.0"
```

## Subpackages

Subpackages determines what algorithms are available to use (as each used library supports different set of algorithms).

**Note:** Not all possible algorithms are implemented yet.

| algorithm  | `:base` | `:phobos` | `:openssl` | `:gnutls` |
| ---------- |:-------:|:---------:|:----------:|:---------:|
| **none**   | &check; |  &check;  |  &check;   |  &check;  |
| **HS256**  |         |  &check;  |  &check;   |  &check;  |
| **HS384**  |         |  &check;  |  &check;   |  &check;  |
| **HS512**  |         |  &check;  |  &check;   |  &check;  |
| **PS256**  |         |           |            |           |
| **PS384**  |         |           |            |           |
| **PS512**  |         |           |            |           |
| **RS256**  |         |           |  &check;   |  &check;  |
| **RS384**  |         |           |  &check;   |  &check;  |
| **RS512**  |         |           |  &check;   |  &check;  |
| **ES256**  |         |           |  &check;   |  &check;  |
| **ES256K** |         |           |            |           |
| **ES384**  |         |           |  &check;   |  &check;  |
| **ES512**  |         |           |  &check;   |  &check;  |
| **edDSA**  |         |           |            |           |

### `:base`

Base definitions and generic JWT operations.
On itself supportd only `JWTAlgorithm.none`, anything else has to be provided in a custom handler.

Sample usage:

```D
import jwtlited;
import std.stdio;

NoneHandler handler;
char[512] token;
enum payload = `{"foo":42}`;
immutable len = handler.encode(token[], payload);
assert(len > 0);
writeln("NONE: ", token[0..len]);

assert(handler.validate(token[0..len]));
char[32] pay;
assert(handler.decode(token[0..len], pay[]));
assert(pay[0..payload.length] == payload);
```

### `:phobos`

Adds HS256, HS384 and HS512 handlers.

Sample usage:

```D
import jwtlited.phobos;
import std.stdio;

HS256Handler handler;
enum payload = `{"foo":42}`;
bool ret = handler.loadKey("foo bar baz");
assert(ret);
char[512] tok;
immutable len = handler.encode(tok[], payload);
assert(len > 0);
writeln("HS256: ", tok[0..len]);

assert(handler.validate(tok[0..len]));
char[32] hdr, pay;
assert(handler.decode(tok[0..len], hdr[], pay[]));
assert(pay[0..payload.length] == payload);
```

### `:openssl`

Adds HMAC, RSA and ECDSA algorithms using [openssl](https://code.dlang.org/packages/openssl) library as a dependency.

Sample usage:

```D
import jwtlited.openssl;
import std.stdio;

enum EC_PRIVKEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILvM6E7mLOdndALDyFc3sOgUTb6iVjgwRBtBwYZngSuwoAoGCCqGSM49
AwEHoUQDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBkNGyQ+P4bc/RmNEq1NpsogiMB
5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==
-----END EC PRIVATE KEY-----`;

ES256Handler handler;
enum payload = `{"foo":42}`;
auto ret = handler.loadPKey(EC_PRIVKEY);
assert(ret);
char[512] tok;
immutable len = handler.encode(tok[], payload);
assert(len > 0);
writeln("ES256: ", tok[0..len]);

enum EC_PUBKEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBk
NGyQ+P4bc/RmNEq1NpsogiMB5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==
-----END PUBLIC KEY-----`;

ret = handler.loadKey(EC_PUBKEY);
assert(ret);
assert(handler.validate(tok[0..len]));
char[32] pay;
assert(handler.decode(tok[0..len], pay[]));
assert(pay[0..payload.length] == payload);
```

### `:gnutls`

Same usage as with `:openssl` but implemented using [GnuTLS](https://gnutls.org/).

At least GnuTLS `v3.5.0` is required.

It has two possible configurations:

* `dynamic` - uses dynamic GnuTLS binding (default)
* `static` - uses static linking with GnuTLS (libgnutls is required)

Configuration can be specified using `subConfiguration` parameter in `dub.sdl` or `dub.json` project file.

## Performance

For example with HS256:

![results](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/results/speed_hs256.png)

For more results see [benchmarks](https://github.com/tchaloupka/jwtlited/blob/main/benchmarks/README.md)
