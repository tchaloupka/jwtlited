/**
 * Module defining various test cases used in separate implementations.
 */
module jwtlited.tests;

version (assert):

import jwtlited.common;
import jwtlited.jwt;

enum Test
{
    decode = 1,
    encode = 2,

    all = decode | encode
}

enum Valid
{
    key = 1,
    decode = 2,
    encode = 4,

    none = 0,
    all = key | decode | encode
}

struct TestCase
{
    string name;
    JWTAlgorithm alg;
    Test test;
    Valid valid;
    string key;
    string pkey;
    string payload;
    string token;
}

immutable TestCase[] testCases = [
    // NONE
    TestCase(
        "NONE - valid",
        JWTAlgorithm.none,
        Test.all, Valid.all,
        null, null,
        `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
    ),
    TestCase(
        "NONE - unexpected signature in token",
        JWTAlgorithm.none,
        Test.decode, Valid.none,
        null, null, null,
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.B02AWclotXRccJUoyHFSpYHMfg4gUvy4cvFrqwMracg",
    ),
    TestCase(
        "NONE - valid token with different algorithm",
        JWTAlgorithm.none,
        Test.decode, Valid.none,
        null, null, null,
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.B02AWclotXRccJUoyHFSpYHMfg4gUvy4cvFrqwMracg",
    ),
    TestCase("NONE - invalid token 1", JWTAlgorithm.none, Test.decode, Valid.none, null, null, null, "aa.bb.cc"),
    TestCase("NONE - invalid token 2", JWTAlgorithm.none, Test.decode, Valid.none, null, null, null, "aa.bb."),
    TestCase("NONE - invalid token 3", JWTAlgorithm.none, Test.decode, Valid.none, null, null, null, "aa.bb"),
    TestCase("NONE - invalid token 4", JWTAlgorithm.none, Test.decode, Valid.none, null, null, null, "aa."),
    TestCase("NONE - invalid token 5", JWTAlgorithm.none, Test.decode, Valid.none, null, null, null, "aa"),
    // HMAC
    TestCase(
        "HS256 - valid decode",
        JWTAlgorithm.HS256,
        Test.decode, Valid.all,
        "FOO BAR BAZ", null,
        `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.B02AWclotXRccJUoyHFSpYHMfg4gUvy4cvFrqwMracg",
    ),
    TestCase(
        "HS256 - valid all",
        JWTAlgorithm.HS256,
        Test.all, Valid.all,
        "FOO BAR BAZ", null,
        `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.9hBU4ACaixzXiNcKiy3P04e4dQmrqVD9gAHVpQoUuBM",
    ),
    TestCase(
        "HS256 - not matching signature - sig",
        JWTAlgorithm.HS256,
        Test.decode, Valid.key,
        "FOO BAR BAZ", null, null,
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.B12AWclotXRccJUoyHFSpYHMfg4gUvy4cvFrqwMracg",
    ),
    TestCase(
        "HS256 - not matching signature - pay",
        JWTAlgorithm.HS256,
        Test.decode, Valid.key,
        "FOO BAR BAZ", null, null,
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzcWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.B02AWclotXRccJUoyHFSpYHMfg4gUvy4cvFrqwMracg",
    ),
    TestCase(
        "HS256 - not matching signature - key",
        JWTAlgorithm.HS256,
        Test.decode, Valid.key,
        "FOOBARBAZ", null, null,
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.B02AWclotXRccJUoyHFSpYHMfg4gUvy4cvFrqwMracg",
    ),
    // ECDSA
    TestCase(
        "ES256 - valid decode",
        JWTAlgorithm.ES256,
        Test.decode, Valid.all,
        `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBk
NGyQ+P4bc/RmNEq1NpsogiMB5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==
-----END PUBLIC KEY-----`,
        null,
        `{"iat":1615393469,"exp":1615394069}`,
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MTUzOTM0NjksImV4cCI6MTYxNTM5NDA2OX0.EdKCi2d44hUfKKipsglMAEj0h9tEdsebgiXwgjxIi1fqlj9wB2LQTVVqhWi7gCYV-Esuj8pfGG3X9YbZtriJ0A",
    ),

// `-----BEGIN EC PRIVATE KEY-----
// MHcCAQEEILvM6E7mLOdndALDyFc3sOgUTb6iVjgwRBtBwYZngSuwoAoGCCqGSM49
// AwEHoUQDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBkNGyQ+P4bc/RmNEq1NpsogiMB
// 5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==
// -----END EC PRIVATE KEY-----`
];

void evalTest(K)(auto ref K key, ref immutable(TestCase) tc) @safe
{
    import std.stdio;
    scope (success) writeln("Test case PASSED: ", tc.name);
    scope (failure) writeln("Test case FAILED: ", tc.name);

    ubyte[512] buf;
    if (tc.test & Test.decode)
    {
        assert(key.decode(tc.token, buf[]) == !!(tc.valid & Valid.decode));
        assert(!(tc.valid & Valid.decode) || buf[0..tc.payload.length] == tc.payload);
        if (tc.valid & Valid.decode)
            assert(key.decode(tc.token, null)); // test validation without payload decode
    }

    if (tc.test & Test.encode)
    {
        auto len = key.encode(buf[], tc.payload);
        if (tc.valid & Valid.encode)
        {
            assert(len == tc.token.length);
            assert(buf[0..len] == tc.token);
        }
        else assert(len == -1);
    }
}

@("JWTAlgorithm.none")
@safe unittest
{
    import std.algorithm : filter;
    import core.memory : GC;

    auto pre = () @trusted { return GC.stats(); }();
    foreach (tc; testCases.filter!(a => a.alg == JWTAlgorithm.none))
    {
        evalTest(None.init, tc);
    }
    assert((() @trusted { return GC.stats().usedSize; }() - pre.usedSize) == 0); // check for no GC allocations
}
