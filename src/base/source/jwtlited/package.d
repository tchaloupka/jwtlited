module jwtlited;

import std.algorithm;
import std.base64;
import std.range : isInputRange, ElementEncodingType;
import std.string;
import std.traits;

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
    import std.range : put;

    // get header part
    immutable hlen = (cast(const(ubyte)[])token).countUntil('.');
    if (hlen <= 0) return false;

    // decode header to check used algorithm
    static String hdrBuf;
    hdrBuf.clear();

    // TODO: should pass, see similar: https://issues.dlang.org/show_bug.cgi?id=18168
    // problem only with OutputRange
    hdrBuf.reserve(Base64URLNoPadding.decodeLength(hlen));
    auto pc = () @trusted { return &hdrBuf[0]; }(); // workaround as Base64.decode doesn't accept char[]
    try () @trusted { Base64URLNoPadding.decode(token[0..hlen], (cast(ubyte*)pc)[0..hdrBuf.length]); }();
    catch (Exception) return false;

    JWTAlgorithm alg;
    immutable algret = parseHeaderAlgorithm(hdrBuf[], alg);
    if (algret != 0) return false;
    if (!validator.isValidAlg(alg)) return false;

    // find end of the payload
    immutable plen = (cast(const(ubyte)[])token[hlen+1..$]).countUntil('.');
    if (plen <= 0) return false;

    // check that sign is the last part of the token
    if ((cast(const(ubyte)[])token[hlen+plen+2..$]).countUntil('.') >= 0) return false; // JWS has only 3 parts

    // copy header if requested
    static if (!is(HS == typeof(null)))
        put(headSink, hdrBuf[]);

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
 * If header is also provided it's checked for correct `alg` header field and added if not set.
 *
 * Both header and payload are expected to be a valid json object serialized string.
 *
 * Returns: -1 on error, otherwise number of characters written to the output.
 */
int encode(S, O, P)(auto ref S signer, auto ref O output, P payload)
    if (isSigner!S && isToken!P)
{
    return encodeImpl!false(signer, output, base64HeaderStrings[signer.signAlg], payload);
}

/// ditto
int encode(S, O, H, P)(auto ref S signer, auto ref O output, H header, P payload)
    if (isSigner!S && isToken!H && isToken!P)
{
    if (header.length) return encodeImpl!true(signer, output, header, payload);
    return encodeImpl!false(signer, output, base64HeaderStrings[signer.signAlg], payload);
}

private int encodeImpl(bool checkHeader, S, O, H, P)(auto ref S signer, auto ref O output, H header, P payload)
    if (isSigner!S && isToken!H && isToken!P)
{
    import std.range : put;

    static String tmp;
    tmp.clear();

    static if (checkHeader)
    {
        assert(header.length);
        if (header[0] != '{' || header[$-1] != '}') return -1;
        JWTAlgorithm alg;
        immutable algret = parseHeaderAlgorithm(header, alg);
        if (algret < -1) return -1;
        if (algret == 0 && alg != signer.signAlg) return -1;
        if (algret == -1)
        {
            String hdrtmp;
            hdrtmp ~= `{"alg":"`;
            hdrtmp ~= algStrings[signer.signAlg];
            hdrtmp ~= `",`;
            hdrtmp ~= header[1..$];
            tmp.reserve(Base64URLNoPadding.encodeLength(hdrtmp.length));
            auto phc = () @trusted { return (cast(ubyte*)&tmp[0])[0..Base64URLNoPadding.encodeLength(hdrtmp.length)]; }();
            Base64URLNoPadding.encode(hdrtmp[], phc);
        }
        else tmp ~= header;
    }
    else tmp ~= header;

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

    put(output, tmp[]);
    return res;
}

unittest
{
    NoneHandler none;
    String buf;
    immutable ret = encode(none, buf, `{"foo":"bar"}`, `{"baz":42}`);
    assert(ret);

    import std.stdio;
    writeln(buf[]);
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

// returns 0 ok, -1 missing, -2 error, -3 unknown or unsupported alg
private int parseHeaderAlgorithm(H)(H hdr, out JWTAlgorithm alg)
    if (isToken!H)
{
    import std.ascii : isAlphaNum, isWhite;

    // pure man's JSON parse to find "alg" in the header
    auto algIdx = hdr.countUntil(`"alg":`);
    if (algIdx < 0) return -1; // alg value is REQUIRED
    algIdx += `"alg":`.length;
    while (algIdx < hdr.length && hdr[algIdx].isWhite) algIdx++; // skip possible whitespaces
    if (algIdx == hdr.length || hdr[algIdx] != '"') return -2;
    auto algStart = ++algIdx;
    // NOTE: expected only alphanum characters for supported JWT algorithms, but needs to be changed to support JWE
    while (algIdx < hdr.length && hdr[algIdx].isAlphaNum) algIdx++;
    if (algIdx == hdr.length || hdr[algIdx] != '"') return -2;
    auto algVal = hdr[algStart..algIdx];

    // get used algorithm
    immutable salg = algStrings.countUntil(algVal);
    if (salg < 0) return -3;
    alg = cast(JWTAlgorithm)salg;
    return 0;
}

struct String
{
    alias C = char;
    @safe nothrow @nogc:

    private
    {
        enum STACK_LEN = 512;
        size_t len;
        C[STACK_LEN] stackBuf;
        C[] buf;
        bool useStackBuf;
        alias pay = typeof(this); // to access fields through pay.xx too
    }

    ~this() pure @trusted
    {
        import core.memory : pureFree;
        if (buf) pureFree(buf.ptr);
    }

    @disable this(this);

    // constructor used by move
    private this(C[] sbuf, C[] buf, size_t len)
    {
        this.stackBuf[0..sbuf.length] = sbuf[];
        this.buf = buf;
        this.len = len;
    }

    String move() scope @trusted
    {
        import std.algorithm : min;
        auto obuf = buf;
        auto olen = len;
        buf = null;
        len = 0;
        return String(stackBuf[0..min(STACK_LEN, olen)], obuf, olen);
    }

    ///
    String clone() scope
    {
        return String(this[]);
    }

    /**
     * Constructor for cases when we know prior to the creation total length of the future string.
     * It preallocates internal buffer with `initialSize`.
     */
    this(size_t len) pure
    {
        if (len <= STACK_LEN) return; // we can use stack buffer for that
        pay.buf = () @trusted { return (cast(C*)enforceMalloc(len * C.sizeof))[0..len]; }();
    }

    this(S)(auto ref scope S str) if (isAcceptableString!S)
    {
        put(str);
    }

    alias data this;

    /**
     * Access internal string including the reserved block if any.
     */
    @property inout(C)[] data() pure inout return
    {
        if (!length) return null;
        if (len <= STACK_LEN) return stackBuf[0..len];
        assert(pay.buf);
        return pay.buf[0..pay.len];
    }

    /// Slicing support for the internal buffer data
    @property inout(C)[] opSlice() pure inout return
    {
        return this.data;
    }

    /// ditto
    @property inout(C)[] opSlice(size_t start, size_t end) pure inout return
    {
        if (start > length || end > length) assert(0, "Index out of bounds");
        if (start > end) assert(0, "Invalid slice indexes");
        return this.data[start .. end];
    }

    /// Indexed access to the buffer data
    @property ref C opIndex(size_t idx) pure return
    {
        if (idx >= length) assert(0, "Index out of bounds");
        return this.data[idx];
    }

    /// opDollar implementation
    alias length opDollar;

    /// Managed string length
    @property size_t length() pure const
    {
        return len;
    }

    /// Returns: capacity that can be used without reallocation
    size_t capacity() pure const
    {
        return (buf ? buf.length : STACK_LEN) - pay.len;
    }

    /**
     * Reserves space for requested number of characters that also increments string length.
     * This can be used for example in cases when we need to fill slice of string with some known length data.
     * To return reserved data, use `dropBack`.
     */
    void reserve(size_t sz)
    {
        ensureAvail(sz);
        pay.len += sz;
    }

    /**
     * Drops defined amount of characters from the back.
     */
    void dropBack(size_t sz)
    {
        assert(length >= sz, "Not enough data");
        if (!sz) return;

        if (len > STACK_LEN && len - sz <= STACK_LEN)
        {
            // switch from heap buffer back to stack one
            len -= sz;
            stackBuf[0..len] = buf[0..len];
            return;
        }
        pay.len -= sz;
    }

    /**
     * Clears content of the data, but keeps internal buffer as is so it can be used to build another string.
     */
    void clear() pure
    {
        len = 0;
    }

    alias opOpAssign(string op : "~") = put;

    void put(in C val) pure
    {
        if (len + 1 <= STACK_LEN)
        {
            stackBuf[len++] = val;
            return;
        }
        ensureAvail(1);
        pay.buf[pay.len++] = val;
    }

    void put(S)(auto ref scope S str) if (isAcceptableString!S)
    {
        alias CF = Unqual!(ElementEncodingType!S);

        static if (C.sizeof == CF.sizeof && is(typeof(pay.buf[0 .. str.length] = str[])))
        {
            if (len + str.length <= STACK_LEN)
            {
                stackBuf[len .. len + str.length] = str[];
                len += str.length;
                return;
            }

            ensureAvail(str.length);
            pay.buf[pay.len .. pay.len + str.length] = str[];
            pay.len += str.length;
        }
        else
        {
            // copy range

            // special case when we can determine that it still fits to stack buffer
            static if (hasLength!S && is(C == CF))
            {
                if (pay.len <= STACK_LEN)
                {
                    foreach (ch; r.byUTF!(Unqual!C))
                    {
                        stackBuf[pay.len++] = ch;
                    }
                    return;
                }
            }

            size_t nlen = pay.len;
            static if (hasLength!S) {
                ensureAvail(str.length);
                nlen += str.length;
            }
            import bc.internal.utf : byUTF;
            static if (isSomeString!S)
                auto r = cast(const(CF)[])str;  // because inout(CF) causes problems with byUTF
            else
                alias r = str;

            foreach (ch; r.byUTF!(Unqual!C))
            {
                static if (!hasLength!S || !is(C == CF))
                {
                    ensureAvail(1);
                    static if (!hasLength!S) nlen++;
                    else {
                        if (pay.len == nlen) nlen++;
                    }
                }
                if (nlen + 1 <= STACK_LEN) // we can still use stack buffer
                {
                    stackBuf[len++] = ch;
                    continue;
                }
                pay.buf[pay.len++] = ch;
            }
            assert(nlen == pay.len);
        }
    }

    private void ensureAvail(size_t sz) pure
    {
        static if (__VERSION__ >= 2094) pragma(inline, true);
        else pragma(inline);
        import core.bitop : bsr;
        import std.algorithm : max, min;

        if (len + sz <= STACK_LEN) return; // still fits to stack buffer
        if (buf is null)
        {
            immutable l = max(len + sz, STACK_LEN + 64); // allocates at leas 64B over
            buf = () @trusted { return (cast(C*)enforceMalloc(l * C.sizeof))[0..l]; }();
            buf[0..len] = stackBuf[0..len]; // copy data from stack buffer,  we'll use heap allocated one from now
            return;
        }
        if (len <= STACK_LEN)
        {
            // some buffer is already preallocated, but we're still on stackBuffer and need to move to heap allocated one
            assert(buf.length > STACK_LEN);
            buf[0..len] = stackBuf[0..len]; // copy current data from the stack
        }

        if (len + sz <= buf.length) return; // we can fit in what we've already allocated

        // reallocate buffer
        // Note: new length calculation taken from std.array.appenderNewCapacity
        immutable ulong mult = 100 + (1000UL) / (bsr((pay.len + sz)) + 1);
        immutable l = cast(size_t)(((pay.len + sz) * min(mult, 200) + 99) / 100);
        // debug printf("realloc %lu -> %lu\n", pay.len, l);
        pay.buf = () @trusted { return (cast(C*)enforceRealloc(pay.buf.ptr, l * C.sizeof))[0..l]; }();
    }
}

// Purified for local use only.
extern (C) @nogc nothrow pure private
{
    pragma(mangle, "malloc") void* fakePureMalloc(size_t) @safe;
    pragma(mangle, "realloc") void* fakePureRealloc(void* ptr, size_t size) @system;
}

void* enforceMalloc()(size_t size) @nogc nothrow pure @safe
{
    auto result = fakePureMalloc(size);
    if (!result)
    {
        version (D_Exceptions)
        {
            import core.exception : onOutOfMemoryError;
            onOutOfMemoryError;
        }
        else assert(0, "Memory allocation failed");
    }
    return result;
}

void* enforceRealloc()(void* ptr, size_t size) @nogc nothrow pure @system
{
    auto result = fakePureRealloc(ptr, size);
    if (!result)
    {
        version (D_Exceptions)
        {
            import core.exception : onOutOfMemoryError;
            onOutOfMemoryError;
        }
        else assert(0, "Memory allocation failed");
    }
    return result;
}

template isAcceptableString(S)
{
    enum isAcceptableString =
        (isInputRange!S || isSomeString!S) &&
        isSomeChar!(ElementEncodingType!S);
}
