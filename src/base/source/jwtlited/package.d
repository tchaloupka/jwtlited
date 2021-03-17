module jwtlited;

import std.algorithm;
import std.base64;
import std.string;
import std.traits;
import bc.string.string;

/// Supported algorithms
enum JWTAlgorithm
{
    none,
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512
}

/**
 * Structure that can be used to handle tokens without signatures.
 * Requires that the token has `"alg": "none"` in the header and no sign part.
 */
struct NoneHandler
{
    @safe pure nothrow @nogc:

    bool isValidAlg(JWTAlgorithm alg)
    {
        return alg == JWTAlgorithm.none;
    }

    bool isValid(V, S)(V value, S sign) if (isToken!V && isToken!S)
    {
        return sign.length == 0;
    }

    JWTAlgorithm signAlg() { return JWTAlgorithm.none; }

    int sign(S, V)(auto ref S sink, auto ref V value)
    {
        return 0;
    }
}

///
@safe unittest
{
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
}

unittest
{
    static assert(isValidator!NoneHandler);
    static assert(isSigner!NoneHandler);
}

/**
 * Validator that accepts any JWT algorithm and ignores it's signature at all.
 * Can be used to decode token without it's signature validation.
 */
struct AnyAlgValidator
{
    @safe pure nothrow @nogc:

    bool isValidAlg(JWTAlgorithm alg) { return true; }

    bool isValid(V, S)(V value, S sign) if (isToken!V && isToken!S)
    {
        return true;
    }
}

unittest
{
    static assert(isValidator!AnyAlgValidator);
    static assert(!isSigner!AnyAlgValidator);
}

private
{
    immutable string[] base64HeaderStrings;
    immutable string[] algStrings;
}

shared static this()
{
    import std.algorithm : map;
    import std.array : array;
    import std.base64 : Base64URLNoPadding;
    import std.format : format;
    import std.traits : EnumMembers;

    // build header hashes for JWT algorithms
    base64HeaderStrings = [EnumMembers!JWTAlgorithm]
        .map!(a => Base64URLNoPadding.encode(cast(ubyte[])(format!`{"alg":"%s"}`(a))))
        .array;

    algStrings = [EnumMembers!JWTAlgorithm].map!(a => format!"%s"(a)).array;
}

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
    if (isToken!T && isValidator!V)
{
    import std.ascii : isAlphaNum, isWhite;
    import std.range : put;

    // get header part
    immutable hlen = (cast(const(ubyte)[])token).countUntil('.');
    if (hlen <= 0) return false;

    // decode header to check used algorithm
    static String hdrBuf;
    hdrBuf.clear();

    // TODO: should pass, see simillar: https://issues.dlang.org/show_bug.cgi?id=18168
    // problem only with OutputRange
    hdrBuf.reserve(Base64URLNoPadding.decodeLength(hlen));
    auto pc = () @trusted { return &hdrBuf[0]; }(); // workaround as Base64.decode doesn't accept char[]
    try () @trusted { Base64URLNoPadding.decode(token[0..hlen], (cast(ubyte*)pc)[0..hdrBuf.length]); }();
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
    {
        static if (isArray!HS)
        {
            assert(headSink.length >= hdrBuf.length);
            headSink[0..hdrBuf.length] = hdrBuf[];
        }
        else static if (__traits(compiles, headSink.put(hdrBuf[])))
            headSink.put(hdrBuf[]);
        else
            hdrBuf[].copy(headSink);
    }

    // decode payload if requested
    static if (!is(PS == typeof(null)))
    {
        static if (isArray!PS && is(ForeachType!PS == char))
        {
            auto ps = () @trusted
            {
                auto p = payloadSink.ptr;
                return (cast(ubyte*)p)[0..payloadSink.length];
            }();
        }
        else alias ps = payloadSink;

        try () @trusted { Base64URLNoPadding.decode(token[hlen+1 .. hlen+plen+1], ps); }(); // TODO: see same problem above
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

/// ditto
bool decode(V, T, S)(auto ref V validator, T token, auto ref S payloadSink)
    if (isToken!T && isValidator!V)
{
    return decode(validator, token, null, payloadSink);
}

/**
 * Decodes token payload without signature validation.
 * Only token header is checked for any "alg" and basic token structure is validated.
 */
bool decodePayload(T, S)(T token, auto ref S payloadSink)
    if (isToken!T)
{
    return decode(AnyAlgValidator.init, token, null, payloadSink);
}

/**
 * Validates token format and signature with a provided validator.
 * It doesn't base64 decode the payload.
 */
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
    import std.range : put;

    static String tmp;
    tmp.clear();

    tmp ~= base64HeaderStrings[signer.signAlg];
    tmp ~= '.';
    auto idx = tmp.length;
    tmp.reserve(Base64URLNoPadding.encodeLength(payload.length));
    auto pc = () @trusted { return (cast(ubyte*)&tmp[idx])[0..Base64URLNoPadding.encodeLength(payload.length)]; }();
    Base64URLNoPadding.encode(payload, pc);
    tmp ~= '.';

    ubyte[512] sigtmp;
    auto len = signer.sign(sigtmp[], tmp[0..$-1]);
    if (len < 0) return -1;

    int res = cast(int)tmp.length;

    if (len)
    {
        idx = tmp.length;
        tmp.reserve(Base64URLNoPadding.encodeLength(len));
        res += Base64URLNoPadding.encode(sigtmp[0..len], tmp[idx..$]).length;
    }

    static if (isArray!O)
    {
        assert(tmp.length <= output.length);
        output[0..tmp.length] = tmp[];
    }
    else static if (__traits(compiles, output.put(tmp[])))
        output.put(tmp[]);
    else
        tmp[].copy(output);
    return res;
}

template isToken(T)
{
    import std.traits : isArray, Unqual, ForeachType;
    enum isToken = isArray!T && is(Unqual!(ForeachType!T) : char);
}

unittest
{
    static assert(isToken!string);
    static assert(isToken!(ubyte[]));
}

template isValidator(V)
{
    enum isValidator = __traits(hasMember, V, "isValidAlg") && __traits(hasMember, V, "isValid");
}

template isSigner(S)
{
    enum isSigner = __traits(hasMember, S, "signAlg") && __traits(hasMember, S, "sign");
}
