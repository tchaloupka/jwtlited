#!/usr/bin/env dub
/+ dub.sdl:
    name "bench_l8w8jwt"
    libs "l8w8jwt" "mbedcrypto" "mbedx509"
+/

module benchmarks.l8w8jwt;

import core.stdc.string;
import std.algorithm;
import std.array;
import std.conv;
import std.datetime.stopwatch;
import std.stdio;
import std.string;

int main(string[] args)
{
    // args: enc/dec/val, cycle count, alg, token/payload, signature
    // output:
    //   payload/token/true
    //   msecs taken
    //   GC used bytes

    if (args.length != 6) { writeln("Invalid args"); return 1; }
    size_t cycles = args[2].to!size_t;

    int alg = args[3].predSwitch(
        "HS256", L8W8JWT_ALG_HS256,
        "HS384", L8W8JWT_ALG_HS384,
        "HS512", L8W8JWT_ALG_HS512,
        "RS256", L8W8JWT_ALG_RS256,
        "RS384", L8W8JWT_ALG_RS384,
        "RS512", L8W8JWT_ALG_RS512,
        "ES256", L8W8JWT_ALG_ES256,
        "ES384", L8W8JWT_ALG_ES384,
        "ES512", L8W8JWT_ALG_ES512,
        -1
    );
    if (alg < 0)
    {
        writeln("Unsupported algorithm");
        return 1;
    }

    {
        StopWatch sw;
        sw.start();
        scope (exit)
        {
            sw.stop();
            writeln(sw.peek.total!"msecs");
            writeln(0); // C library, no GC used
        }

        if (args[1] == "val") return validate(cycles, alg, args[4], args[5]);
        else if (args[1] == "dec") return decode(cycles, alg, args[4], args[5]);
        else if (args[1] == "enc") return encode(cycles, alg, args[4], args[5]);
    }

    writeln("Invalid command: ", args[1]);
    return 1;
}

int validate(size_t cycles, int alg, string token, string secret)
{
    l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);
    params.alg = alg;
    bool ret;
    foreach (_; 0..cycles)
    {
        params.jwt = cast(char*)token.ptr;
        params.jwt_length = token.length;

        params.verification_key = cast(ubyte*)secret.ptr;
        params.verification_key_length = secret.length;

        l8w8jwt_validation_result validation_result;
        immutable r = l8w8jwt_decode(&params, &validation_result, null, null);
        ret = !r && validation_result == l8w8jwt_validation_result.L8W8JWT_VALID;
    }

    writeln(ret);
    return 0;
}

int decode(size_t cycles, int alg, string token, string secret)
{
    l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);
    params.alg = alg;
    size_t claims_length;
    l8w8jwt_claim* claims;

    bool ret;
    foreach (_; 0..cycles)
    {
        params.jwt = cast(char*)token.ptr;
        params.jwt_length = token.length;

        params.verification_key = cast(ubyte*)secret.ptr;
        params.verification_key_length = secret.length;

        l8w8jwt_validation_result validation_result;
        if (claims) l8w8jwt_free_claims(claims, claims_length);
        immutable r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
        if (r || validation_result != l8w8jwt_validation_result.L8W8JWT_VALID)
        {
            writeln("Failed to decode token. r=", r, ", res=", validation_result);
            return 1;
        }
    }

    chillbuff cb;
    chillbuff_init(&cb, 32, 1, chillbuff_growth_method.CHILLBUFF_GROW_DUPLICATIVE);
    assert(claims && claims_length > 1);
    l8w8jwt_write_claims(&cb, claims+1, claims_length-1); // workaround - skip first as it has alg from header
    l8w8jwt_free_claims(claims, claims_length);
    scope (exit) chillbuff_free(&cb);
    writeln('{', (cast(char*)cb.array)[0..cb.length], '}');

    return 0;
}

int encode(size_t cycles, int alg, string payload, string secret)
{
    // prep claims - not all data types handled properly, but enough for the test
    import std.json, std.typecons;
    auto jpay = parseJSON(payload);
    auto cl = jpay.object.byKeyValue.map!(a => tuple(a.key, a.value.type.predSwitch(
        JSONType.string, a.value.str,
        JSONType.integer, a.value.integer.to!string
    ), a.value.type == JSONType.string ? L8W8JWT_CLAIM_TYPE_STRING : L8W8JWT_CLAIM_TYPE_INTEGER)).array;

    l8w8jwt_claim[] payload_claims =
        cl.map!(a => l8w8jwt_claim(
            cast(char*)a[0].ptr,
            a[0].length,
            cast(char*)a[1].ptr,
            a[1].length,
            a[2]
        )).array;

    char* jwt;
    size_t jwt_length;
    l8w8jwt_encoding_params params;
    l8w8jwt_encoding_params_init(&params);
    params.alg = alg;
    params.secret_key = cast(ubyte*)secret.ptr;
    params.secret_key_length = secret.length;
    params.out_ = &jwt;
    params.out_length = &jwt_length;

    foreach (_; 0..cycles)
    {
        if (jwt) l8w8jwt_free(jwt);
        immutable r = l8w8jwt_encode(&params);
        if (r)
        {
            writeln("Error encoding token: ", r);
            return 1;
        }
    }

    scope (exit) l8w8jwt_free(jwt);
    writeln(jwt[0..jwt_length]);
    return 0;
}

// bindings
extern(C) nothrow @nogc:

import core.sys.posix.sys.select;

enum L8W8JWT_ALG_HS256 = 0;
enum L8W8JWT_ALG_HS384 = 1;
enum L8W8JWT_ALG_HS512 = 2;
enum L8W8JWT_ALG_RS256 = 3;
enum L8W8JWT_ALG_RS384 = 4;
enum L8W8JWT_ALG_RS512 = 5;
enum L8W8JWT_ALG_PS256 = 6;
enum L8W8JWT_ALG_PS384 = 7;
enum L8W8JWT_ALG_PS512 = 8;
enum L8W8JWT_ALG_ES256 = 9;
enum L8W8JWT_ALG_ES384 = 10;
enum L8W8JWT_ALG_ES512 = 11;
enum L8W8JWT_ALG_ES256K = 12;
enum L8W8JWT_ALG_ED25519 = 13;

enum l8w8jwt_validation_result
{
    /**
     * The JWT is valid (according to the passed validation parameters).
     */
    L8W8JWT_VALID = cast(uint) 0,

    /**
     * The issuer claim is invalid.
     */
    L8W8JWT_ISS_FAILURE = cast(uint) 1 << cast(uint) 0,

    /**
     * The subject claim is invalid.
     */
    L8W8JWT_SUB_FAILURE = cast(uint) 1 << cast(uint) 1,

    /**
     * The audience claim is invalid.
     */
    L8W8JWT_AUD_FAILURE = cast(uint) 1 << cast(uint) 2,

    /**
     * The JWT ID claim is invalid.
     */
    L8W8JWT_JTI_FAILURE = cast(uint) 1 << cast(uint) 3,

    /**
     * The token is expired.
     */
    L8W8JWT_EXP_FAILURE = cast(uint) 1 << cast(uint) 4,

    /**
     * The token is not yet valid.
     */
    L8W8JWT_NBF_FAILURE = cast(uint) 1 << cast(uint) 5,

    /**
     * The token was not issued yet, are you from the future?
     */
    L8W8JWT_IAT_FAILURE = cast(uint) 1 << cast(uint) 6,

    /**
     * The token was potentially tampered with: its signature couldn't be verified.
     */
    L8W8JWT_SIGNATURE_VERIFICATION_FAILURE = cast(uint) 1 << cast(uint) 7,

    /**
     * The token's "typ" claim validation failed.
     */
    L8W8JWT_TYP_FAILURE = cast(uint) 1 << cast(uint) 8
}

/**
 * Struct containing the parameters to use for decoding and validating a JWT.
 */
struct l8w8jwt_decoding_params
{
    /**
     * The token to decode and validate.
     */
    char* jwt;

    /**
     * The jwt string length.
     */
    size_t jwt_length;

    /**
     * The signature algorithm ID. <p>
     * [0;2] = HS256/384/512 | [3;5] = RS256/384/512 | [6;8] = PS256/384/512 | [9;11] = ES256/384/512 <p>
     * This affects what should be the value of {@link #verification_key}
     */
    int alg;

    /**
     * [OPTIONAL] The issuer claim (who issued the JWT?). <p>
     * Set to <code>NULL</code> if you don't want to validate the issuer. <p>
     * The JWT will only pass verification if its <code>iss</code> claim matches this string.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    char* validate_iss;

    /**
     * validate_iss string length.
     */
    size_t validate_iss_length;

    /**
     * [OPTIONAL] The subject claim (who is the JWT about?). <p>
     * Set to <code>NULL</code> if you don't want to validate the subject claim. <p>
     * The JWT will only pass verification if its <code>sub</code> matches this string.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    char* validate_sub;

    /**
     * validate_sub string length.
     */
    size_t validate_sub_length;

    /**
     * [OPTIONAL] The audience claim (who is the JWT intended for? Who is the intended JWT's recipient?). <p>
     * Set to <code>NULL</code> if you don't want to validate the audience. <p>
     * The JWT will only pass verification if its <code>aud</code> matches this string.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    char* validate_aud;

    /**
     * validate_aud string length.
     */
    size_t validate_aud_length;

    /**
     * [OPTIONAL] The JWT ID. Provides a unique identifier for the token. <p>
     * Set to <code>NULL</code> if you don't want to validate the jti claim. <p>
     * The JWT will only pass verification if its <code>jti</code> matches this string.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.7
     */
    char* validate_jti;

    /**
     * validate_jti claim length.
     */
    size_t validate_jti_length;

    /**
     * Should the expiration claim be verified?
     * If this is set to <code>1</code>, the <code>exp</code> claim will be compared to the current date and time + {@link #exp_tolerance_seconds}
     */
    int validate_exp;

    /**
     * Should the "not before" claim be verified?
     * If this is set to <code>1</code>, the <code>nbf</code> claim will be compared to the current date and time + {@link #nbf_tolerance_seconds}
     */
    int validate_nbf;

    /**
     * Should the "issued at" claim be verified?
     * If this is set to <code>1</code>, the <code>iat</code> claim will be compared to the current date and time + {@link #iat_tolerance_seconds}
     */
    int validate_iat;

    /**
     * Small inconsistencies in time can happen, or also latency between clients and servers.
     * That's just life. You can forgive a few seconds of expiration, but don't exaggerate this! <p>
     * Only taken into consideration if {@link #validate_exp} is set to <code>1</code>.
     */
    ubyte exp_tolerance_seconds;

    /**
     * The amount of seconds to subtract from the current time when comparing the "not before" claim, to allow for a small tolerance time frame.
     * Only taken into consideration if {@link #validate_nbf} is set to <code>1</code>.
     */
    ubyte nbf_tolerance_seconds;

    /**
     * The amount of seconds to subtract from the current time when comparing the "issued at" claim, to allow for a small tolerance time frame.
     * Only taken into consideration if {@link #validate_iat} is set to <code>1</code>.
     */
    ubyte iat_tolerance_seconds;

    /**
     * The key to use for verifying the token's signature
     * (e.g. if you chose HS256 as algorithm, this will be the HMAC secret; for RS512 this will be the PEM-formatted public RSA key string, etc...).
     */
    ubyte* verification_key;

    /**
     * Length of the {@link #verification_key}
     */
    size_t verification_key_length;

    /**
     * [OPTIONAL] The typ claim (what type is the token?). <p>
     * Set to <code>NULL</code> if you don't want to validate the "typ" claim. <p>
     */
    char* validate_typ;

    /**
     * validate_typ string length.
     */
    size_t validate_typ_length;
}

/**
 * Initializes a {@link #l8w8jwt_decoding_params} instance by setting its fields to default values.
 * @param params The l8w8jwt_decoding_params to initialize (set to default values).
 */
void l8w8jwt_decoding_params_init (l8w8jwt_decoding_params* params);

/**
 * Validates a set of l8w8jwt_decoding_params.
 * @param params The l8w8jwt_decoding_params to validate.
 * @return Return code as defined in retcodes.h
 */
int l8w8jwt_validate_decoding_params (l8w8jwt_decoding_params* params);

/**
 * Decode (and validate) a JWT using specific parameters. <p>
 * The resulting {@link #l8w8jwt_validation_result} written into the passed "out_validation_result" pointer
 * contains validation failure flags (see the {@link #l8w8jwt_validation_result} enum docs for more details). <p>
 * This only happens if decoding also succeeded: if the token is malformed, nothing will be written into "out_validation_result". <p>
 * If validation succeeds, the {@link #l8w8jwt_validation_result} receives the value 0 (enum value <code>L8W8JWT_VALID</code>). <p>
 * The same applies to the "out_claims" argument: it is only allocated and written to if it (obviously) isn't <code>NULL</code> and if the decoding was also successful!
 *
 * @param params The parameters to use for decoding and validating the token.
 *
 * @param out_validation_result Where to write the validation result flags into (0 means success). In case of a decoding failure this is set to -1 (or <code>~L8W8JWT_VALID</code>)!
 *
 * @param out_claims
 * [OPTIONAL] Where the decoded claims (header + payload claims together) should be written into.
 * This pointer will be dereferenced + allocated, so make sure to pass a fresh pointer!
 * If you don't need the claims, set this to <code>NULL</code> (they will only be validated, e.g. signature, exp, etc...).
 * Check the note down below for more infos!
 *
 * @param out_claims_length Where to write the decoded claims count into. This will receive the value of how many claims were written into "out_claims" (0 if you decided to set "out_claims" to <code>NULL</code>).
 *
 * @note If you decide to keep the claims stored in the <code>out_claims</code> parameter, REMEMBER to call {@link #l8w8jwt_free_claims()} on it once you're done using them!
 *
 * @return Return code as defined in retcodes.h (this is NOT the validation result that's written into the out_validation_result argument; the returned int describes whether the actual parsing/decoding part failed).
 */
int l8w8jwt_decode (l8w8jwt_decoding_params* params, l8w8jwt_validation_result* out_validation_result, l8w8jwt_claim** out_claims, size_t* out_claims_length);
enum L8W8JWT_MAX_KEY_SIZE = 8192;

/**
 * JWT claim value is a string (e.g. <code>"iss": "glitchedpolygons.com"</code>).
 */
enum L8W8JWT_CLAIM_TYPE_STRING = 0;

/**
 * JWT claim value is an integer (e.g. <code>"exp": 1579610629</code>)
 */
enum L8W8JWT_CLAIM_TYPE_INTEGER = 1;

/**
 * JWT claim value type number (e.g. <code>"size": 1.85</code>).
 */
enum L8W8JWT_CLAIM_TYPE_NUMBER = 2;

/**
 * JWT claim value is a boolean (e.g. <code>"done": true</code>).
 */
enum L8W8JWT_CLAIM_TYPE_BOOLEAN = 3;

/**
 * JWT claim value is null (e.g. <code>"ref": null</code>).
 */
enum L8W8JWT_CLAIM_TYPE_NULL = 4;

/**
 * JWT claim value type JSON array (e.g. <code>"ids": [2, 4, 8, 16]</code>).
 */
enum L8W8JWT_CLAIM_TYPE_ARRAY = 5;

/**
 * JWT claim value type is a JSON object (e.g. <code>"objs": { "name": "GMan", "id": 420 }</code>).
 */
enum L8W8JWT_CLAIM_TYPE_OBJECT = 6;

/**
 * JWT claim value is some other type.
 */
enum L8W8JWT_CLAIM_TYPE_OTHER = 7;

/**
 * Struct containing a jwt claim key-value pair.<p>
 * If allocated on the heap by the decode function,
 * remember to call <code>l8w8jwt_claims_free()</code> on it once you're done using it.
 */
struct l8w8jwt_claim
{
    /**
     * The token claim key (e.g. "iss", "iat", "sub", etc...). <p>
     * NUL-terminated C-string!
     */
    char* key;

    /**
     * key string length. <p>
     * Set this to <code>0</code> if you want to make the encoder use <code>strlen(key)</code> instead.
     */
    size_t key_length;

    /**
     * The claim's value as a NUL-terminated C-string.
     */
    char* value;

    /**
     * value string length. <p>
     * Set this to <code>0</code> if you want to make the encoder use <code>strlen(value)</code> instead.
     */
    size_t value_length;

    /**
     * The type of the claim's value. <p>
     * 0 = string, 1 = integer, 2 = number, 3 = boolean, 4 = null, 5 = array, 6 = object, 7 = other.
     * @see https://www.w3schools.com/js/js_json_datatypes.asp
     */
    int type;
}

/**
 * Frees a heap-allocated <code>l8w8jwt_claim</code> array.
 * @param claims The claims to free.
 * @param claims_count The size of the passed claims array.
 */
void l8w8jwt_free_claims (l8w8jwt_claim* claims, size_t claims_count);

/**
 * Writes a bunch of JWT claims into a chillbuff stringbuilder. <p>
 * Curly braces and trailing commas won't be written; only the "key":"value" pairs!
 * @param stringbuilder The buffer into which to write the claims.
 * @param claims The l8w8jwt_claim array of claims to write.
 * @param claims_count The claims array size.
 * @return Return code as specified inside retcodes.h
 */
int l8w8jwt_write_claims (chillbuff* stringbuilder, l8w8jwt_claim* claims, size_t claims_count);

/**
 * Gets a claim by key from a l8w8jwt_claim array.
 * @param claims The array to look in.
 * @param claims_count The claims array size.
 * @param key The claim key (e.g. "sub") to look for.
 * @param key_length The claim key's string length.
 * @return The found claim; <code>NULL</code> if no such claim was found in the array.
 */
l8w8jwt_claim* l8w8jwt_get_claim (l8w8jwt_claim* claims, size_t claims_count, const(char)* key, size_t key_length);

/**
 * Struct containing the parameters to use for creating a JWT with l8w8jwt.
 */
struct l8w8jwt_encoding_params
{
    /**
     * The signature algorithm ID. <p>
     * [0;2] = HS256/384/512 | [3;5] = RS256/384/512 | [6;8] = PS256/384/512 | [9;11] = ES256/384/512
     */
    int alg;

    /**
     * [OPTIONAL] The issuer claim (who issued the JWT?). Can be omitted by setting this to <code>NULL</code>.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    char* iss;

    /**
     * iss claim string length.
     */
    size_t iss_length;

    /**
     * [OPTIONAL] The subject claim (who is the JWT about?). Set to <code>NULL</code> if you don't want it in your token.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    char* sub;

    /**
     * sub claim string length.
     */
    size_t sub_length;

    /**
     * [OPTIONAL] The audience claim (who is the JWT intended for? Who is the intended JWT's recipient?).
     * Set this to <code>NULL</code> if you don't wish to add this claim to the token.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    char* aud;

    /**
     * aud claim string length.
     */
    size_t aud_length;

    /**
     * [OPTIONAL] The JWT ID. Provides a unique identifier for the token. Can be omitted by setting this to <code>NULL</code>.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.7
     */
    char* jti;

    /**
     * jti claim string length.
     */
    size_t jti_length;

    /**
     * Expiration time claim; specifies when this token should stop being valid (in seconds since Unix epoch). <p>
     * If you want to omit this, set this to <code>0</code>, but do NOT FORGET to set it to something,
     * otherwise it will be set to whatever random value was in the memory where this variable resides.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.4
     */
    time_t exp;

    /**
     * "Not before" time claim; specifies when this token should start being valid (in seconds since Unix epoch). <p>
     * If you want to omit this, set this to <code>0</code>, but do NOT FORGET to set it to something,
     * otherwise it will be set to whatever random value was in the memory where this variable resides.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.5
     */
    time_t nbf;

    /**
     * "Issued at" timestamp claim; specifies when this token was emitted (in seconds since Unix epoch). <p>
     * If you want to omit this, set this to <code>0</code>, but do NOT FORGET to set it to something,
     * otherwise it will be set to whatever random value was in the memory where this variable resides.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.6
     */
    time_t iat;

    /**
     * [OPTIONAL] Array of additional claims to include in the JWT's header like for example "kid" or "cty"; pass <code>NULL</code> if you don't wish to add any! <p>
     * Avoid header claims such as <code>typ</code> and <code>alg</code>, since those are written by the encoding function itself.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.7
     */
    l8w8jwt_claim* additional_header_claims;

    /**
     * [OPTIONAL] The additional_header_claims array size; pass <code>0</code> if you don't wish to include any custom claims!
     */
    size_t additional_header_claims_count;

    /**
     * [OPTIONAL] Array of additional claims to include in the JWT's payload; pass <code>NULL</code> if you don't wish to add any! <p>
     * Registered claim names such as "iss", "exp", etc... have their own dedicated field within this struct: do not include those in this array to prevent uncomfortable duplicates!
     * @see https://tools.ietf.org/html/rfc7519#section-4
     */
    l8w8jwt_claim* additional_payload_claims;

    /**
     * [OPTIONAL] The additional_payload_claims array size; pass <code>0</code> if you don't wish to include any custom claims!
     */
    size_t additional_payload_claims_count;

    /**
     * The secret key to use for signing the token
     * (e.g. if you chose HS256 as algorithm, this will be the HMAC secret; for RS512 this will be the private PEM-formatted RSA key string, and so on...).
     */
    ubyte* secret_key;

    /**
     * Length of the secret_key
     */
    size_t secret_key_length;

    /**
     * If the secret key requires a password for usage, please assign it to this field. <p>
     * You can only omit this when using JWT algorithms "HS256", "HS384" or "HS512" (it's ignored in that case actually). <p>
     * Every other algorithm requires you to at least set this to <code>NULL</code> if the {@link #secret_key} isn't password-protected.
     */
    ubyte* secret_key_pw;

    /**
     * The secret key's password length (if there is any). If there's none, set this to zero!
     */
    size_t secret_key_pw_length;

    /**
     * Where the encoded token should be written into
     * (will be malloc'ed, so make sure to <code>l8w8jwt_free()</code> this as soon as you're done using it!).
     */
    char** out_;

    /**
     * Where the output token string length should be written into.
     */
    size_t* out_length;
}

/**
 * Initializes a {@link #l8w8jwt_encoding_params} instance by setting its fields to default values.
 * @param params The l8w8jwt_encoding_params to initialize (set to default values).
 */
void l8w8jwt_encoding_params_init (l8w8jwt_encoding_params* params);

/**
 * Validates a set of l8w8jwt_encoding_params.
 * @param params The l8w8jwt_encoding_params to validate.
 * @return Return code as defined in retcodes.h
 */
int l8w8jwt_validate_encoding_params (l8w8jwt_encoding_params* params);

/**
 * Creates, signs and encodes a Json-Web-Token. <p>
 * An example output could be: <code>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNvbWUta2V5LWlkLWhlcmUtMDEyMzQ1NiJ9.eyJpYXQiOjE1Nzk2NDUzNTUsImV4cCI6MTU3OTY0NTk1NSwic3ViIjoiR29yZG9uIEZyZWVtYW4iLCJpc3MiOiJCbGFjayBNZXNhIiwiYXVkIjoiQWRtaW5pc3RyYXRvciJ9.uk4EEoq0ql_SguLto5EWzklakpzO-6GE2U26crB8vUY</code> <p>
 * @param params The token encoding parameters (e.g. "alg", "iss", "exp", etc...).
 * @return Return code as defined in retcodes.h
 * @see l8w8jwt_encoding_params
 */
int l8w8jwt_encode (l8w8jwt_encoding_params* params);

void l8w8jwt_free(void* mem);

// chillbuff bindings

/**
 * How should the chillbuff's underlying array grow in size
 * once its maximum capacity is reached during a push_back?
 */
enum chillbuff_growth_method
{
    /**
     * Double the capacity.
     */
    CHILLBUFF_GROW_DUPLICATIVE = 0,

    /**
     * Triple the capacity.
     */
    CHILLBUFF_GROW_TRIPLICATIVE = 1,

    /**
     * Grow by the same capacity every time the buffer is full.
     */
    CHILLBUFF_GROW_LINEAR = 2,

    /**
     * Multiplies the capacity by itself. Not the greatest idea... Use carefully!
     */
    CHILLBUFF_GROW_EXPONENTIAL = 3
}

/**
 * Self-reallocating dynamic size array of no strictly defined type.
 * Easy 'n' "chill" (hope you like segmentation fault errors).
 */
struct chillbuff
{
    /**
     * The buffer's underlying array that stores the data.
     */
    void* array;

    /**
     * The current amount of elements stored in the chillbuff. DO NOT touch this yourself, only read!
     */
    size_t length;

    /**
     * The current buffer capacity. This grows dynamically according to the specified {@link #chillbuff_growth_method}.
     */
    size_t capacity;

    /**
     * The size of each stored element. DO NOT CHANGE THIS! Only read (if necessary)...
     */
    size_t element_size;

    /**
     * The way the buffer's capacity is increased when it's full.
     */
    chillbuff_growth_method growth_method;
}

/**
 * Initializes a chillbuff instance and makes it ready to accept data.
 * @param buff The chillbuff instance to init (or rather, a pointer to it).
 * @param initial_capacity The initial capacity of the underlying array. If you pass <code>0</code> here, <code>16</code> is used by default.
 * @param element_size How big should every array element be? E.g. if you're storing <code>int</code> you should pass <code>sizeof(int)</code>.
 * @param growth_method How should the buffer grow once its maximum capacity is reached? @see chillbuff_growth_method
 * @return Chillbuff exit code as defined at the top of the chillbuff.h header file. <code>0</code> means success.
 */
int chillbuff_init (
    chillbuff* buff,
    const size_t initial_capacity,
    const size_t element_size,
    const chillbuff_growth_method growth_method)
{
    import core.stdc.stdlib;
    buff.array = malloc(min(16, initial_capacity)*element_size);
    buff.capacity = min(16, initial_capacity);
    buff.element_size = element_size;
    buff.growth_method = growth_method;
    return 0;
}

/**
 * Frees a chillbuff instance.
 * @param buff The chillbuff to deallocate. If this is <code>NULL</code>, nothing happens at all.
 */
void chillbuff_free (chillbuff* buff)
{
    import core.stdc.stdlib;
    free(buff.array);
}

// /**
//  * Clears a chillbuff's data. <p>
//  * Deletes all of the underlying array's elements and resets the length to <code>0</code>. <p>
//  * Leaves the array allocated at the current capacity.
//  * @param buff The chillbuff to clear. If this is <code>NULL</code>, nothing happens at all.
//  */
// void chillbuff_clear (chillbuff* buff);
