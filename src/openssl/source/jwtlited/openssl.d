module jwtlited.openssl;

public import jwtlited;
version (assert) import core.stdc.stdio;

import deimos.openssl.ec;
import deimos.openssl.err;
import deimos.openssl.evp;
import deimos.openssl.hmac;
import deimos.openssl.pem;
import deimos.openssl.sha;

import core.exception : onOutOfMemoryError;

// some missing OpenSSL symbols
extern(C) nothrow @nogc
{
    void EVP_MD_CTX_free(EVP_MD_CTX* ctx);
    EVP_MD_CTX* EVP_MD_CTX_new();
    int ECDSA_SIG_set0(ECDSA_SIG* sig, BIGNUM* r, BIGNUM* s);
    void ECDSA_SIG_get0(const(ECDSA_SIG)* sig, const BIGNUM** pr, const BIGNUM** ps);
}

alias HS256Handler = HMACImpl!(JWTAlgorithm.HS256);
alias HS384Handler = HMACImpl!(JWTAlgorithm.HS384);
alias HS512Handler = HMACImpl!(JWTAlgorithm.HS512);

/**
 * Implementation of HS256, HS384 and HS512 signing algorithms.
 */
private struct HMACImpl(JWTAlgorithm implAlg)
{
    static if (implAlg == JWTAlgorithm.HS256) enum signLen = SHA256_DIGEST_LENGTH;
    else static if (implAlg == JWTAlgorithm.HS384) enum signLen = SHA384_DIGEST_LENGTH;
    else static if (implAlg == JWTAlgorithm.HS512) enum signLen = SHA512_DIGEST_LENGTH;
    else static assert(0, "Unsupprted algorithm for HMAC implementation");

    private
    {
        const(char)[] key;
        HMAC_CTX ctx;
        ubyte[signLen] sigBuf;
    }

    @disable this(this);

    ~this() @trusted
    {
        HMAC_CTX_reset(&ctx);
    }

    bool loadKey(K)(K key) if (isToken!K)
    {
        if (!key.length) return false;
        this.key = cast(const(char)[])key;

        auto ret = () @trusted
        {
            static if (implAlg == JWTAlgorithm.HS256) alias evp = EVP_sha256;
            else static if (implAlg == JWTAlgorithm.HS384) alias evp = EVP_sha384;
            else static if (implAlg == JWTAlgorithm.HS512) alias evp = EVP_sha512;

            HMAC_CTX_reset(&ctx);
            return HMAC_Init_ex(&ctx, this.key.ptr, cast(int)key.length, evp(), null);
        }();
        if (!ret) return false;
        return true;
    }

    bool isValidAlg(JWTAlgorithm alg) { return implAlg == alg; }

    bool isValid(V, S)(V value, S sign) if (isToken!V && isToken!S)
    {
        if (!genSignature(value)) return false;
        return cast(const(ubyte)[])sign == sigBuf[0..signLen];
    }

    JWTAlgorithm signAlg() { return implAlg; }

    int sign(S, V)(auto ref S sink, auto ref V value) if (isToken!V)
    {
        import std.algorithm : copy;
        if (!genSignature(value)) return -1;
        sigBuf[0..signLen].copy(sink);
        return signLen;
    }

    private bool genSignature(V)(V value) @trusted
    {
        assert(key.length, "Secret key not set");
        if (!key.length || !value.length) return false;

        scope (exit) HMAC_Init_ex(&ctx, null, 0, null, null);

        auto ret = HMAC_Update(&ctx, cast(const(ubyte)*)value.ptr, cast(ulong)value.length);
        if (!ret) return false;

        uint slen;
        ret = HMAC_Final(&ctx, sigBuf.ptr, &slen);
        assert(slen == signLen);
        if (!ret) return false;
        return true;
    }
}

alias RS256Handler = PEMImpl!(JWTAlgorithm.RS256);
alias RS384Handler = PEMImpl!(JWTAlgorithm.RS384);
alias RS512Handler = PEMImpl!(JWTAlgorithm.RS512);
alias ES256Handler = PEMImpl!(JWTAlgorithm.ES256);
alias ES384Handler = PEMImpl!(JWTAlgorithm.ES384);
alias ES512Handler = PEMImpl!(JWTAlgorithm.ES512);

/**
 * Implementation of ES256, ES384 and ES512 signing algorithms.
 */
private struct PEMImpl(JWTAlgorithm implAlg)
{
    private
    {
        EVP_PKEY* pubKey;
        EVP_PKEY* privKey;
        EVP_MD_CTX* mdctxPriv;
        EVP_MD_CTX* mdctxPub;

        import std.algorithm : among;
        static if (implAlg.among(JWTAlgorithm.ES256, JWTAlgorithm.ES384, JWTAlgorithm.ES512))
        {
            enum type = EVP_PKEY_EC;
            int slen;
        }
        else static if (implAlg.among(JWTAlgorithm.RS256, JWTAlgorithm.RS384, JWTAlgorithm.RS512))
            enum type = EVP_PKEY_RSA;
        else static assert(0, "Unsupprted algorithm for PEM implementation");

        static if (implAlg == JWTAlgorithm.ES256) alias evp = EVP_sha256;
        else static if (implAlg == JWTAlgorithm.ES384) alias evp = EVP_sha384;
        else static if (implAlg == JWTAlgorithm.ES512) alias evp = EVP_sha512;
        else static if (implAlg == JWTAlgorithm.RS256) alias evp = EVP_sha256;
        else static if (implAlg == JWTAlgorithm.RS384) alias evp = EVP_sha384;
        else static if (implAlg == JWTAlgorithm.RS512) alias evp = EVP_sha512;
    }

    @disable this(this);

    ~this() @trusted
    {
        if (pubKey) EVP_PKEY_free(pubKey);
        if (privKey) EVP_PKEY_free(privKey);
        if (mdctxPub) EVP_MD_CTX_free(mdctxPub);
        if (mdctxPriv) EVP_MD_CTX_free(mdctxPriv);
    }

    bool loadKey(K)(K key) @trusted if (isToken!K)
    {
        if (!key.length) return false;

        BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, cast(int)key.length);
        if (!bpo) onOutOfMemoryError;
        scope (exit) BIO_free(bpo);

        // TODO: Uses OpenSSL's default passphrase callbacks if needed.
        pubKey = PEM_read_bio_PUBKEY(bpo, null, null, null);
        if (!pubKey)
        {
            version (assert) ERR_print_errors_fp(stderr);
            return false;
        }

        auto pkeyType = EVP_PKEY_id(pubKey);
        if (pkeyType != type) return false;

        // Convert EC sigs back to ASN1.
        static if (type == EVP_PKEY_EC)
        {
            // Get the actual ec_key
            auto ec_key = EVP_PKEY_get1_EC_KEY(pubKey);
            if (!ec_key) onOutOfMemoryError();
            immutable degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));
            EC_KEY_free(ec_key);

            immutable bn_len = (degree + 7) / 8;
            slen = bn_len * 2;
        }

        mdctxPub = EVP_MD_CTX_new();
        if (!mdctxPub) onOutOfMemoryError();

        return true;
    }

    bool loadPKey(K)(K key) @trusted if (isToken!K)
    {
        if (!key.length) return false;

        BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, cast(int)key.length);
        if (!bpo) onOutOfMemoryError;
        scope (exit) BIO_free(bpo);

        // TODO: Uses OpenSSL's default passphrase callbacks if needed.
        privKey = PEM_read_bio_PrivateKey(bpo, null, null, null);
        if (!privKey)
        {
            version (assert) ERR_print_errors_fp(stderr);
            return false;
        }

        auto pkeyType = EVP_PKEY_id(privKey);
        if (pkeyType != type) return false;

        mdctxPriv = EVP_MD_CTX_new();
        if (!mdctxPriv) onOutOfMemoryError();

        return true;
    }

    bool isValidAlg(JWTAlgorithm alg) { return implAlg == alg; }

    bool isValid(V, S)(V value, S sign) @trusted if (isToken!V && isToken!S)
    {
        version (unittest) {} // no assert behavior is tested in unittest
        else assert(pubKey, "Public key not set");
        if (!value.length || !sign.length || !pubKey) return false;

        static if (type == EVP_PKEY_EC)
        {
            if (sign.length != slen) return false;

            ubyte[72] sbuf;
            immutable bn_len = slen / 2;
            auto ec_sig_r = BN_bin2bn(sign.ptr, bn_len, null);
            auto ec_sig_s = BN_bin2bn(sign.ptr + bn_len, bn_len, null);
            if (!ec_sig_r || !ec_sig_s) return false;

            auto ec_sig = ECDSA_SIG_new();
            if (!ec_sig) onOutOfMemoryError;
            scope (exit) ECDSA_SIG_free(ec_sig);
            if (ECDSA_SIG_set0(ec_sig, ec_sig_r, ec_sig_s) != 1) return false;

            auto siglen = i2d_ECDSA_SIG(ec_sig, null);
            assert(siglen <= sbuf.length);
            auto p = &sbuf[0];
            siglen = i2d_ECDSA_SIG(ec_sig, &p);
            if (siglen == 0) return false;
            auto psig = &sbuf[0];
        }
        else
        {
            auto psig = sign.ptr;
            immutable siglen = cast(int)sign.length;
        }

        // Initialize the DigestVerify operation using evp algorithm
        if (EVP_DigestVerifyInit(mdctxPub, null, evp, null, pubKey) != 1)
            return false;

        if (EVP_DigestVerifyUpdate(mdctxPub, value.ptr, value.length) != 1)
            return false;

        auto ret = EVP_DigestVerifyFinal(mdctxPub, psig, siglen);
        if (ret == -1)
        {
            version (assert) ERR_print_errors_fp(stderr);
            return false;
        }
        return ret == 1;
    }

    JWTAlgorithm signAlg() { return implAlg; }

    int sign(S, V)(auto ref S sink, auto ref V value) @trusted
    {
        import std.algorithm : copy;

        version (unittest) {} // no assert behavior is tested in unittest
        else assert(privKey, "Private key not set");
        if (!privKey) return -1;

        // Initialize the DigestSign operation using alg
        if (EVP_DigestSignInit(mdctxPriv, null, evp, null, privKey) != 1)
            return -1;

        // Call update with the message
        if (EVP_DigestSignUpdate(mdctxPriv, value.ptr, value.length) != 1)
            return -1;

        // First, call EVP_DigestSignFinal with a null sig parameter to get length of sig.
        ubyte[512] sig;
        size_t slen;
        if (EVP_DigestSignFinal(mdctxPriv, null, &slen) != 1)
            return -1;

        assert(sig.length >= slen);

        // Get the signature with real length
        if (EVP_DigestSignFinal(mdctxPriv, &sig[0], &slen) != 1)
            return -1;

        static if (type != EVP_PKEY_EC) sig[0..slen].copy(sink); // just return the signature as is
        else
        {
            // For EC we need to convert to a raw format of R/S.
            auto ec_key = EVP_PKEY_get1_EC_KEY(privKey); // Get the actual ec_key
            if (!ec_key) onOutOfMemoryError();
            immutable degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));
            EC_KEY_free(ec_key);

            // Get the sig from the DER encoded version
            ubyte* ps = cast(ubyte*)sig.ptr;
            auto ec_sig = d2i_ECDSA_SIG(null, cast(const(ubyte)**)&ps, slen);
            if (!ec_sig) onOutOfMemoryError();
            scope (exit) ECDSA_SIG_free(ec_sig);

            const BIGNUM* ec_sig_r;
            const BIGNUM* ec_sig_s;
            ECDSA_SIG_get0(ec_sig, &ec_sig_r, &ec_sig_s);
            immutable r_len = BN_num_bytes(ec_sig_r);
            immutable s_len = BN_num_bytes(ec_sig_s);
            immutable bn_len = (degree + 7) / 8;
            if ((r_len > bn_len) || (s_len > bn_len))
                return -1;

            ubyte[512] buf;
            slen = 2 * bn_len;
            assert(buf.length >= slen);

            // Pad the bignums with leading zeroes
            BN_bn2bin(ec_sig_r, buf.ptr + bn_len - r_len);
            BN_bn2bin(ec_sig_s, buf.ptr + slen - s_len);

            buf[0..slen].copy(sink);
        }

        return cast(int)slen;
    }
}

///
@safe unittest
{
    import jwtlited.openssl;
    import std.stdio;

    enum EC_PUBKEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBk
NGyQ+P4bc/RmNEq1NpsogiMB5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==
-----END PUBLIC KEY-----`;

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

    ret = handler.loadKey(EC_PUBKEY);
    assert(ret);
    assert(handler.validate(tok[0..len]));
    char[32] pay;
    assert(handler.decode(tok[0..len], pay[]));
    assert(pay[0..payload.length] == payload);
}

@safe unittest
{
    static assert(isValidator!HS256Handler);
    static assert(isSigner!HS256Handler);
    static assert(isValidator!ES256Handler);
    static assert(isSigner!ES256Handler);
    static assert(isValidator!RS256Handler);
    static assert(isSigner!RS256Handler);
}

@("ECDSA - Test fail on uninitialized keys")
@safe unittest
{
    ES256Handler h;
    char[512] token;
    immutable len = h.encode(token[], `{"foo":42}`);
    assert(len < 0);
    assert(!h.validate("eyJhbGciOiJFUzI1NiJ9.eyJmb28iOjQyfQ.R_MeWV0nLqRcNk9OrczuhykhKJn2wBZIgmwF87TivMlLGk2KB4Ekec9aXz0dOxBfYQflP6PwdSNjgLdYMECwRA"));
}

version (unittest) import jwtlited.tests;

@("OpenSSL tests")
@safe unittest
{
    static void eval(H)(ref immutable TestCase tc)
    {
        H h;
        static if (is(H == HS256Handler) || is(H == HS384Handler) || is(H == HS512Handler))
            assert(h.loadKey(tc.key) == !!(tc.valid & Valid.key));
        else
        {
            if (tc.test & Test.decode)
                assert(h.loadKey(tc.key) == !!(tc.valid & Valid.key));
            if (tc.test & Test.encode)
                assert(h.loadPKey(tc.pkey) == !!(tc.valid & Valid.key));
        }

        evalTest(h, tc);
    }

    static auto allocatedInCurrentThread() @trusted
    {
        import core.memory : GC;
        static if (__VERSION__ >= 2094) return GC.allocatedInCurrentThread();
        else return GC.stats().allocatedInCurrentThread;
    }

    import std.algorithm : canFind, filter;

    immutable pre = allocatedInCurrentThread();

    with (JWTAlgorithm)
    {
        static immutable testAlgs = [
            HS256, HS384, HS512,
            RS256, RS384, RS512,
            ES256, ES384, ES512
        ];

        foreach (tc; testCases.filter!(a => testAlgs.canFind(a.alg)))
        {
            final switch (tc.alg)
            {
                case none: assert(0);
                case HS256: eval!HS256Handler(tc); break;
                case HS384: eval!HS384Handler(tc); break;
                case HS512: eval!HS512Handler(tc); break;

                case RS256: eval!RS256Handler(tc); break;
                case RS384: eval!RS384Handler(tc); break;
                case RS512: eval!RS512Handler(tc); break;

                case ES256: eval!ES256Handler(tc); break;
                case ES384: eval!ES384Handler(tc); break;
                case ES512: eval!ES512Handler(tc); break;
            }
        }
    }

    assert(allocatedInCurrentThread() - pre == 0); // check for no GC allocations
}
