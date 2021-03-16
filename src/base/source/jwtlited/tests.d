/**
 * Module defining various test cases used in separate implementations.
 */
module jwtlited.tests;

version (assert):

import jwtlited;

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

enum EC256_PUBKEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBk
NGyQ+P4bc/RmNEq1NpsogiMB5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==
-----END PUBLIC KEY-----`;

enum EC256_PRIVKEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILvM6E7mLOdndALDyFc3sOgUTb6iVjgwRBtBwYZngSuwoAoGCCqGSM49
AwEHoUQDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBkNGyQ+P4bc/RmNEq1NpsogiMB
5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==
-----END EC PRIVATE KEY-----`;

enum EC512_PUBKEY = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBb6j/jJ/+D25Ez8GuU3Al+DsnuZXF
AkU6V2eMMezgJu/6E0+FCUMcLaIi6MAuBo74FE6MSCCW4CQ3MGOG75jy67EBENM7
xGFOBWlBedku4S7N4cayJbpHVnxc+Z5uK50gchiUripQ1i78wi7W+5WjYYQBUE4l
4et/HP21c5n4LRCeasw=
-----END PUBLIC KEY-----`;

enum EC512_PRIVKEY = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIATbhPa+N94KjXbTzHx3ujwN+TwLVlQjyxA2e1jp8oYxogg8S/ceXU
CsS/169A1zf1EYKe7lEYm3LTSXcvdaXzT1ygBwYFK4EEACOhgYkDgYYABAFvqP+M
n/4PbkTPwa5TcCX4Oye5lcUCRTpXZ4wx7OAm7/oTT4UJQxwtoiLowC4GjvgUToxI
IJbgJDcwY4bvmPLrsQEQ0zvEYU4FaUF52S7hLs3hxrIlukdWfFz5nm4rnSByGJSu
KlDWLvzCLtb7laNhhAFQTiXh638c/bVzmfgtEJ5qzA==
-----END EC PRIVATE KEY-----`;

enum RS_PRIVKEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0hZf4ct1tvPkcqM7826L89TwCPBhuycWMn3xT+4MLeUqe51F
LMSm1VK6k+Ew8jrmQ9T9tOtp2vRJFEhoK/WVAb44Sg0PuX9zDLw8ncgW9jON4q6X
m9MeJNC2Mb5ogwc72S+kQWNWi3nNR9xrCXmczHfoolVC9/lnU0T+Tp7kj4MZNmSC
Cx0eACHpkZV5306TAs+FSlOpKgTL9Wazf1i7teTddkhD5Csm/OE5gBqdAQDqO/8q
aKDpmYJTdrjM8RebBq9eTuc5sp7zzIGH2hjveiBG7+/83dDgLwW5IUV1+EB/VqSx
jrlurQcH38zYfmXV65QCToJXbF5X3asUluSu9wIDAQABAoIBAQCfXV2qeJ55BBW9
aFnn1WnQsyzKex6Hy6So9KSDD36pqfdKAgkhZqNvmuvxlZd9iHR37C/wd8u6zihJ
fIuZHRfFVLh6Y+ITwrxRYtFQlyHj7UOqOurCx6lMIA61OU0qZ+hcXilpeKOD9gdk
ha2kaF4rNKKB0c+VL9nTbrjChwG2YkneqROL7KyszVHAumU9sZUtaYsxKvwALwZi
7GStXCa8yFb0AXuTANWzVQt5QsFvIO5GpXjQrmYJM36pwzKNVKBFCqrMrRoQhuwe
UfXOI/VF1tUM9BhZ78R/ccxBGyklQCJt2wO1GqnWKH1lUDHUTDv//V3kI4TF8Tba
lEn4l8fhAoGBAPYIVsjDZdi7LTnkXENlUTf+VvWGwM7Upb7QK0LK6rZkJrFeiLfT
vPd4TDEcNHcWVKz+dZubJ5m1rC8hh4IUsQv5CcZdcQuJ/dINZyPRyNkNU4O+kDmf
50xemRMm9JwpvJfSRsIzoFizzwNsvYeJpQm5ZbGHdVxM1kQBt0P05Hk/AoGBANqZ
PWLTcKh942GXDzlr6sg4067neYg5fKMeUU6QsDN5Zf6MmPBNDDVd5+oMTjxRQiSW
Q4SIqR2ssDDuowBGBSoAirQyTdiQ/lVo4/h9oQJX2fDEQvMsPSaby6MBzl9kSSPz
fBeqSM5fCt6HpkLvzIwS6AlQ4lFzj3fU7tZ3vuRJAoGAGr6FUIWNCKYwIF7meJ0G
2yNWqJHhW5pZ+gf+69/K69CvNBCmo/TsUapN/fim61sOEVAH0MZo45iQAv+OD2HY
bQjBO0LlCvARG0hBse8X+iAst+F7JAhxyCdwVFijtmYDDi3ZazrZb0r8cc7cO2OH
ASuaFlY3N7VShUn6dfSk8VkCgYB0RawUI9k5lfRbFUlgxpkUNL3Lu422OrWj4d1n
h6hhSMJKmihDMQg8Xp2brT3z8VjYMyDonvQtN4xkCpqi65uVksI0RMmJVt4hOfCA
XPpGT8o5uXrO84n3PkkbhDtsG+CXgcxQnh+pvX3/jXGPCxPmsavAQMiQgIIgQB9l
7j2YGQKBgERkwz7s29PN9jg/9D0UGynxhkvJhIo8EcN42/lrnr4MziHxIHN5CwBv
oNHVKMZXklzzZ7X2jZcqY5UbTIOwiDonwmjfch8SSHt4L50MIzaCrxzDaEQ//zd6
qT7bwBrcVfn7JUE8RRk5qEn5Z81Z/4AciYBFbsOowA/1NDhLoCZ5
-----END RSA PRIVATE KEY-----`;

    enum RS_PUBKEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0hZf4ct1tvPkcqM7826L
89TwCPBhuycWMn3xT+4MLeUqe51FLMSm1VK6k+Ew8jrmQ9T9tOtp2vRJFEhoK/WV
Ab44Sg0PuX9zDLw8ncgW9jON4q6Xm9MeJNC2Mb5ogwc72S+kQWNWi3nNR9xrCXmc
zHfoolVC9/lnU0T+Tp7kj4MZNmSCCx0eACHpkZV5306TAs+FSlOpKgTL9Wazf1i7
teTddkhD5Csm/OE5gBqdAQDqO/8qaKDpmYJTdrjM8RebBq9eTuc5sp7zzIGH2hjv
eiBG7+/83dDgLwW5IUV1+EB/VqSxjrlurQcH38zYfmXV65QCToJXbF5X3asUluSu
9wIDAQAB
-----END PUBLIC KEY-----`;

/// Test cases to test correct validation and signature used with all implementations
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

    // RSA
    TestCase(
        "RS512 - valid",
        JWTAlgorithm.RS512,
        Test.all, Valid.all, RS_PUBKEY, RS_PRIVKEY,
        `{"foo":42}`,
        "eyJhbGciOiJSUzUxMiJ9.eyJmb28iOjQyfQ.HawDMFOZBczB6PozCDPMG4LVYqiy9UaOghs7-ccfQfOpm8nnUNjIcC7-_bUi_KK7tcKUqPIjnz7aR89szjNu5-CtiAef62xfbsPq6ZCTh0x57GNHHMa1DBYoLkvMeRmbKdFgEcamh6qEIoGiihGoe11O3J1JoX6-bktDHNmHEBAYK1BzyxLo2yYwYBPa6GoxOV-qM1ysX_4FEqIul9EpAahLX1S5H9MYwiWt4e7yhRYyJgLXM2qPNCzXrVG28QcF5dSnDjzzvdi8urScBFmVnFKWhZrQj3VbvwOUkJFbaYd4eN2rzTBNQV2YQjU9KZL0kJMn2AcnTeyG_IBj34E8Ig"
    ),
    TestCase(
        "RS512 - different alg",
        JWTAlgorithm.RS512,
        Test.decode, Valid.key, RS_PUBKEY, RS_PRIVKEY,
        `{"foo":42}`,
        "eyJhbGciOiJSUzI1NiJ9.eyJmb28iOjQyfQ.BOHqKf2MlxWvUNEm8TQIlJ2XIigRN9Mesgt88VrpbnjPBhi5r3J_82pi-iX60RscddpXkFS5f0YZxB-rDslPaZEh_P12SXN9QCEuqspeh7_uFbZpG0E2RcKpjvs4N4UnOetEVkcn1GxjZoZEkzffH-tNGFlLQeRVyJPuk1D8cH13JsKbpmqGQayQOmlZjYsdM48Yy0Rb5Pcc0tR95zBXtQtkgeBNYNEBN5lfWaLBpTADm-fJV5dw4Hu3qKvOMOzW2CslIsCTq-1c-VT4I6-hSBlhy2GkozhKKtbGS6G4RpunolX5GOaPiqhKcQx12TnBVqotRMfEJKazkZe3MA80QA"
    ),
    TestCase(
        "RS256 - valid",
        JWTAlgorithm.RS256,
        Test.all, Valid.all, RS_PUBKEY, RS_PRIVKEY,
        `{"foo":42}`,
        "eyJhbGciOiJSUzI1NiJ9.eyJmb28iOjQyfQ.BOHqKf2MlxWvUNEm8TQIlJ2XIigRN9Mesgt88VrpbnjPBhi5r3J_82pi-iX60RscddpXkFS5f0YZxB-rDslPaZEh_P12SXN9QCEuqspeh7_uFbZpG0E2RcKpjvs4N4UnOetEVkcn1GxjZoZEkzffH-tNGFlLQeRVyJPuk1D8cH13JsKbpmqGQayQOmlZjYsdM48Yy0Rb5Pcc0tR95zBXtQtkgeBNYNEBN5lfWaLBpTADm-fJV5dw4Hu3qKvOMOzW2CslIsCTq-1c-VT4I6-hSBlhy2GkozhKKtbGS6G4RpunolX5GOaPiqhKcQx12TnBVqotRMfEJKazkZe3MA80QA"
    ),

    // ECDSA
    TestCase(
        "ES256 - valid",
        JWTAlgorithm.ES256,
        Test.all, Valid.all, EC256_PUBKEY, EC256_PRIVKEY,
        `{"foo":42}`,
        "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOjQyfQ.R_MeWV0nLqRcNk9OrczuhykhKJn2wBZIgmwF87TivMlLGk2KB4Ekec9aXz0dOxBfYQflP6PwdSNjgLdYMECwRA"
    ),
    TestCase(
        "ES512 - valid",
        JWTAlgorithm.ES512,
        Test.all, Valid.all, EC512_PUBKEY, EC512_PRIVKEY,
        `{"foo":42}`,
        "eyJhbGciOiJFUzUxMiJ9.eyJmb28iOjQyfQ.AGjGpLTYdQB2U2amD6-zJAWI0buCUiKgu-hT_JJgDmqyXYjSvJRQ3uaWID3DWj5fISsMoFZNdp29Pn8Rzwn4yWXYADX_4H4OLUb-IZ82qDfVgZNVMlygrvevbczGU-v1FpKac5Ov2CC7irEoCgus-kVhgFe2XscCz5T6UxUmn4V59Jc3"
    ),
];

void evalTest(H)(auto ref H handler, ref immutable(TestCase) tc) @safe
{
    import std.algorithm : countUntil;
    import std.range : retro;
    import std.stdio : writeln;
    scope (success) writeln("Test case PASSED: ", tc.name);
    scope (failure) writeln("Test case FAILED: ", tc.name);

    char[512] buf;
    if (tc.test & Test.decode)
    {
        assert(handler.decode(tc.token, buf[]) == !!(tc.valid & Valid.decode));
        assert(!(tc.valid & Valid.decode) || buf[0..tc.payload.length] == tc.payload);
        if (tc.valid & Valid.decode)
            assert(handler.decode(tc.token, null)); // test validation without payload decode
    }

    if (tc.test & Test.encode)
    {
        immutable len = handler.encode(buf[], tc.payload);
        if (tc.valid & Valid.encode)
        {
            assert(len == tc.token.length);

            // some algorithms generates different signature, so we check if it's valid and only part vithout the signature equals
            immutable idx = tc.token.retro.countUntil('.');
            assert(idx >= 0); // NONE ends with '.'

            if (tc.test & Test.decode)
                assert(handler.validate(buf[0..len]));

            assert(buf[0..tc.token.length-idx] == tc.token[0..$-idx]);
        }
        else assert(len == -1);
    }
}

@("JWTAlgorithm.none")
@safe unittest
{
    import std.algorithm : filter;
    import core.memory : GC;

    immutable pre = () @trusted { return GC.stats(); }();
    foreach (tc; testCases.filter!(a => a.alg == JWTAlgorithm.none))
    {
        evalTest(NoneHandler.init, tc);
    }
    assert((() @trusted { return GC.stats().usedSize; }() - pre.usedSize) == 0); // check for no GC allocations
}

@("AnyAlgValidator")
@safe unittest
{
    // valid token
    enum tok = "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.";
    enum hdr = `{"alg":"none"}`;
    enum pay = `{"foo":"bar"}`;
    char[64] bh, bp;

    // decode header and payload
    assert(decode(AnyAlgValidator.init, tok, bh[], bp[]));
    assert(bh[0..hdr.length] == hdr);
    assert(bp[0..pay.length] == pay);

    // decode payload
    assert(decode(AnyAlgValidator.init, tok, bp[]));
    assert(bp[0..pay.length] == pay);

    // just validate
    assert(validate(AnyAlgValidator.init, tok));

    // invalid base64 signature
    assert(!validate(AnyAlgValidator.init, "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.blabla!"));
}
