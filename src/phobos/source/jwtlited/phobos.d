module jwtlited.phobos;

public import jwtlited;

alias HS256Handler = HMACImpl!(JWTAlgorithm.HS256);
alias HS384Handler = HMACImpl!(JWTAlgorithm.HS384);
alias HS512Handler = HMACImpl!(JWTAlgorithm.HS512);

/**
 * Implementation of HS256, HS384 and HS512 signing algorithms.
 */
private struct HMACImpl(JWTAlgorithm implAlg)
{
    import std.digest.hmac : HMAC;
    import std.digest.sha : SHA256, SHA384, SHA512;

    static if (implAlg == JWTAlgorithm.HS256) {
        enum signLen = 32;
        alias SHA = SHA256;
    } else static if (implAlg == JWTAlgorithm.HS384) {
        enum signLen = 48;
        alias SHA = SHA384;
    } else static if (implAlg == JWTAlgorithm.HS512) {
        enum signLen = 64;
        alias SHA = SHA512;
    }
    else static assert(0, "Unsupprted algorithm for HMAC implementation");

    private const(ubyte)[] key;

    bool loadKey(K)(K key) if (isToken!K)
    {
        if (!key.length) return false;
        this.key = cast(const(ubyte)[])key;
        return true;
    }

    bool isValidAlg(JWTAlgorithm alg) { return implAlg == alg; }

    bool isValid(V, S)(V value, S sign) if (isToken!V && isToken!S)
    {
        assert(key.length, "Secret key not set");
        if (!key.length || !value.length || sign.length != signLen) return false;

        immutable sig = HMAC!SHA(key)
            .put(cast(const(ubyte)[])value)
            .finish();
        assert(sig.length == signLen);
        return cast(const(ubyte)[])sign == sig[];
    }

    JWTAlgorithm signAlg() { return implAlg; }

    int sign(S, V)(auto ref S sink, auto ref V value) if (isToken!V)
    {
        import std.algorithm : copy;

        assert(key.length, "Secret key not set");
        if (!key.length || !value.length) return false;

        HMAC!SHA(key)
            .put(cast(const(ubyte)[])value)
            .finish()[]
            .copy(sink);
        return signLen;
    }
}

///
@safe unittest
{
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
}

@safe unittest
{
    static assert(isValidator!HS256Handler);
    static assert(isSigner!HS256Handler);
}

version (unittest) import jwtlited.tests;

@("Phobos tests")
@safe unittest
{
    static void eval(H)(ref immutable TestCase tc)
    {
        H h;
        assert(h.loadKey(tc.key) == !!(tc.valid & Valid.key));
        evalTest(h, tc);
    }

    import std.algorithm : canFind, filter;

    with (JWTAlgorithm)
    {
        static immutable testAlgs = [HS256, HS384, HS512];

        foreach (tc; testCases.filter!(a => testAlgs.canFind(a.alg)))
        {
            switch (tc.alg)
            {
                case HS256: eval!HS256Handler(tc); break;
                case HS384: eval!HS384Handler(tc); break;
                case HS512: eval!HS512Handler(tc); break;
                default: assert(0);
            }
        }
    }
}
