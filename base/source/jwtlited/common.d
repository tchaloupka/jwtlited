module jwtlited.common;

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
    enum isValidator = __traits(hasMember, V, "alg") && __traits(hasMember, V, "isValid");
}

template isSigner(S)
{
    enum isSigner = __traits(hasMember, S, "alg") && __traits(hasMember, S, "sign");
}

/**
 * Structure that can be used to handle tokens without signatures
 */
struct None
{
    immutable JWTAlgorithm alg = JWTAlgorithm.none;

    bool isValid(V, S)(V value, S sign) if (isToken!V && isToken!S)
    {
        return sign.length == 0;
    }

    int sign(S, V)(auto ref S sink, auto ref V value)
    {
        return 0;
    }
}

unittest
{
    static assert(isValidator!None);
    static assert(isSigner!None);
}

package (jwtlited)
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
