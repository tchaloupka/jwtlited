module jwtlited.jwt;

import std.algorithm;
import std.base64;
import std.string;
import std.traits;
import bc.string.string;

import jwtlited.common;

// TODO: use SSE4.2 optimised token parser to also check for invalid characters in token while advancing between '.'

/**
 * Decodes and validates the JWT token.
 *
 * It always base64 decode the header and checks "alg" value in it.
 * Payload is decoded only when payloadSink is provided, otherwise it's just skipped.
 * Sign part is base64 decoded and passed to the provided validator implementation to check.
 *
 * JSON header and payload validation is out of scope of this function. It just checks the basic structure of JWT.
 * Note: Only compact encoded JWS format is supported.
 */
bool decode(V, T, HS, PS)(auto ref V validator, T token, auto ref HS headSink, auto ref PS payloadSink)
    if(isToken!T && isValidator!V)
{
    import std.ascii : isAlphaNum, isWhite;

    // get header part
    immutable hlen = (cast(const(ubyte)[])token).countUntil('.');
    if (hlen <= 0) return false;

    // decode header to check used algorithm
    static String hdrBuf;
    hdrBuf.clear();

    // TODO: should pass, see simillar: https://issues.dlang.org/show_bug.cgi?id=18168
    // problem only with OutputRange
    try () @trusted { Base64URLNoPadding.decode(token[0..hlen], hdrBuf); }();
    catch (Exception) return false;

    // pure man's JSON parse to find "alg" in the header
    auto algIdx = hdrBuf[].countUntil(`"alg":`);
    if (algIdx < 0) return false; // alg value is REQUIRED
    algIdx += `"alg":`.length;
    while (algIdx < hdrBuf.length && hdrBuf[algIdx].isWhite) algIdx++; // skip possible whitespaces
    if (algIdx == hdrBuf.length || hdrBuf[algIdx] != '"') return false;
    auto algStart = ++algIdx;
    // NOTE: expected only alphanum characters for supported JWT algorithms, but needs to be changed to support JWE
    while (algIdx < hdrBuf.length && hdrBuf[algIdx].isAlphaNum) algIdx++;
    if (algIdx == hdrBuf.length || hdrBuf[algIdx] != '"') return false;
    auto algVal = hdrBuf[algStart..algIdx];

    // get used algorithm
    immutable salg = algStrings.countUntil(algVal);
    if (salg < 0) return false;
    immutable alg = cast(JWTAlgorithm)salg;
    if (!validator.isValidAlg(alg)) return false;

    // find end of the payload
    immutable plen = (cast(const(ubyte)[])token[hlen+1..$]).countUntil('.');
    if (plen <= 0) return false;

    // check that sign is the last part of the token
    if ((cast(const(ubyte)[])token[hlen+plen+2..$]).countUntil('.') >= 0) return false; // JWS has only 3 parts

    // copy header if requested
    static if (!is(HS == typeof(null)))
        hdrBuf[].copy(headSink);

    // decode payload if requested
    static if (!is(PS == typeof(null)))
    {
        try () @trusted { Base64URLNoPadding.decode(token[hlen+1 .. hlen+plen+1], payloadSink); }(); // TODO: see same problem above
        catch (Exception) return false;
    }

    // validate signature with the provided validator
    ubyte[512] sigBuf; // RSA 4096 has 512B sign, we don't expect more)
    auto sigB64 = token[hlen+plen+2..$];
    ubyte[] sig;
    if (sigB64.length)
    {
        if (Base64URLNoPadding.decodeLength(sigB64.length) > sigBuf.length) return false;
        try sig = Base64URLNoPadding.decode(sigB64, sigBuf[]);
        catch (Exception) return false;
    }
    return validator.isValid(token[0..hlen+plen+1], sig);
}

bool decode(V, T, S)(auto ref V validator, T token, auto ref S payloadSink)
    if(isToken!T && isValidator!V)
{
    return decode(validator, token, null, payloadSink);
}

bool validate(V, T)(auto ref V validator, T token)
{
    return decode(validator, token, null, null);
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

    tmp ~= base64HeaderStrings[signer.signAlg];
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
