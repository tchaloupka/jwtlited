module jwtlited.jwt;

import std.algorithm;
import std.base64;
import std.string;
import std.traits;
import bc.string.string;

import jwtlited.common;

// TODO: use SSE4.2 optimised token parser to also check for invalid characters in token while advancing between '.'

bool decode(V, T, S)(auto ref V validator, T token, auto ref S payloadSink)
    if(isToken!T && isValidator!V)
{
    import std.ascii : isAlphaNum, isWhite;

    // get header part
    auto hlen = (cast(const(ubyte)[])token).countUntil('.');
    if (hlen <= 0) return false;

    // decode header to check used algorithm
    static String hdrBuf;
    hdrBuf.clear();

    // TODO: should pass, see simillar: https://issues.dlang.org/show_bug.cgi?id=18168
    // problem only with OutputRange
    auto hdr = () @trusted { return Base64URLNoPadding.decode(token[0..hlen], hdrBuf); }();

    // pure man's JSON parse to find "alg" in the header
    auto algIdx = hdrBuf[].countUntil(`"alg":`);
    if (algIdx < 0) return false; // alg value is REQUIRED
    algIdx += `"alg":`.length;
    while (algIdx < hdrBuf.length && hdrBuf[algIdx].isWhite) algIdx++; // skip possible whitespaces
    if (algIdx == hdrBuf.length || hdrBuf[algIdx] != '"') return false;
    auto algStart = ++algIdx;
    while (algIdx < hdrBuf.length && hdrBuf[algIdx].isAlphaNum) algIdx++; // expected only alphanum characters for supported JWT algorithms
    if (algIdx == hdrBuf.length || hdrBuf[algIdx] != '"') return false;
    auto algVal = hdrBuf[algStart..algIdx];

    import std.uni : sicmp;
    import std.stdio;
    if (sicmp(algVal, algStrings[validator.alg]) != 0) return false;

    auto plen = (cast(const(ubyte)[])token[hlen+1..$]).countUntil('.');
    if (plen <= 0) return false;
    if (hlen+plen+2 == token.length && validator.alg != JWTAlgorithm.none) return false;

    if ((cast(const(ubyte)[])token[hlen+plen+2..$]).countUntil('.') >= 0) return false; // JWS has only 3 parts

    // decode payload if requested
    static if (!is(S == typeof(null)))
    {
        () @trusted { Base64URLNoPadding.decode(token[hlen+1 .. hlen+plen+1], payloadSink); }(); // TODO: see same problem above
    }

    ubyte[512] sigBuf; // RSA 4096 has 512B sign, we don't expect more)
    auto sigB64 = token[hlen+plen+2..$];
    ubyte[] sig;
    if (sigB64.length)
    {
        if (Base64URLNoPadding.decodeLength(sigB64.length) > sigBuf.length) return false;
        sig = Base64URLNoPadding.decode(sigB64, sigBuf[]);
    }
    return validator.isValid(token[0..hlen+plen+1], sig);
}

/**
 * Endodes token using provided Singer algorithm and already prepared payload.
 *
 * Returns: -1 on error, otherwise number of characters written to the output.
 */
int encode(S, O, P)(auto ref S signer, auto ref O output, P payload)
    if (isSigner!S && isToken!P)
{
    import std.algorithm : copy;

    static String tmp;
    tmp.clear();

    tmp ~= base64HeaderStrings[signer.alg];
    tmp ~= '.';
    Base64URLNoPadding.encode(payload, tmp);
    tmp ~= '.';

    ubyte[512] sigtmp;
    auto len = signer.sign(sigtmp[], tmp[0..$-1]);
    if (len < 0) return -1;

    int res = cast(int)tmp.length;

    if (len)
        res += Base64URLNoPadding.encode(sigtmp[0..len], tmp);

    tmp[].copy(output);
    return res;
}
