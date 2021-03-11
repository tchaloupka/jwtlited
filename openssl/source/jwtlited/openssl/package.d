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

// some missing symbols
extern(C) nothrow @nogc
{
    void EVP_MD_CTX_free(EVP_MD_CTX* ctx);
    EVP_MD_CTX* EVP_MD_CTX_new();
    int ECDSA_SIG_set0(ECDSA_SIG* sig, BIGNUM* r, BIGNUM* s);
}

alias HS256Handler = HMACImpl!(JWTAlgorithm.HS256);
alias HS384Handler = HMACImpl!(JWTAlgorithm.HS384);
alias HS512Handler = HMACImpl!(JWTAlgorithm.HS512);

/**
 * Implementation of HS256, HS384 and HS512 signing algorithms.
 */
private struct HMACImpl(JWTAlgorithm implAlg)
{
    private
    {
        const(char)[] key;
        HMAC_CTX ctx;
        ubyte[SHA512_DIGEST_LENGTH] sigBuf;
    }

    static if (implAlg == JWTAlgorithm.HS256) enum signLen = SHA256_DIGEST_LENGTH;
    else static if (implAlg == JWTAlgorithm.HS384) enum signLen = SHA384_DIGEST_LENGTH;
    else static if (implAlg == JWTAlgorithm.HS512) enum signLen = SHA512_DIGEST_LENGTH;
    else static assert(0, "Unsupprted algorithm for HMAC implementation");

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

    int sign(S, V)(auto ref S sink, auto ref V value)
    {
        import std.algorithm : copy;
        if (!genSignature(value)) return -1;
        sigBuf[0..signLen].copy(sink);
        return signLen;
    }

    private bool genSignature(V)(V value) @trusted
    {
        assert(key.length);
        if (!value.length) return false;

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

alias ES256Handler = ECDSAImpl!(JWTAlgorithm.ES256);
alias ES384Handler = ECDSAImpl!(JWTAlgorithm.ES384);
alias ES512Handler = ECDSAImpl!(JWTAlgorithm.ES512);

/**
 * Implementation of ES256, ES384 and ES512 signing algorithms.
 */
private struct ECDSAImpl(JWTAlgorithm implAlg)
{
    private
    {
        EVP_PKEY* pubkey;
        EVP_MD_CTX* mdctx;

        import std.algorithm : among;
        static if (implAlg.among(JWTAlgorithm.ES256, JWTAlgorithm.ES384, JWTAlgorithm.ES512))
        {
            enum type = EVP_PKEY_EC;
            int slen;
        }
        else static assert(0, "Unsupprted algorithm for ECDSA implementation");

        static if (implAlg == JWTAlgorithm.ES256) alias evp = EVP_sha256;
        else static if (implAlg == JWTAlgorithm.ES384) alias evp = EVP_sha384;
        else static if (implAlg == JWTAlgorithm.ES512) alias evp = EVP_sha512;
    }

    @disable this(this);

    ~this() @trusted
    {
        if (pubkey) EVP_PKEY_free(pubkey);
        if (mdctx) EVP_MD_CTX_free(mdctx);
    }

    bool loadKey(K)(K key) @trusted if (isToken!K)
    {
        if (!key.length) return false;

        BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, cast(int)key.length);
        if (!bpo) onOutOfMemoryError;
        scope (exit) BIO_free(bpo);

        // TODO: Uses OpenSSL's default passphrase callbacks if needed.
        pubkey = PEM_read_bio_PUBKEY(bpo, null, null, null);
        if (!pubkey)
        {
            version (assert) ERR_print_errors_fp(stderr);
            return false;
        }

        auto pkeyType = EVP_PKEY_id(pubkey);
        if (pkeyType != type) return false;

        // Convert EC sigs back to ASN1.
        static if (type == EVP_PKEY_EC)
        {
            // Get the actual ec_key
            auto ec_key = EVP_PKEY_get1_EC_KEY(pubkey);
            if (!ec_key) onOutOfMemoryError();
            auto degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));
            EC_KEY_free(ec_key);

            auto bn_len = (degree + 7) / 8;
            slen = bn_len * 2;
        }

        mdctx = EVP_MD_CTX_new();
        if (!mdctx) onOutOfMemoryError();

        return true;
    }

    bool loadPKey(K)(K key)
    {
        return false;
    }

    bool isValidAlg(JWTAlgorithm alg) { return implAlg == alg; }

    bool isValid(V, S)(V value, S sign) @trusted if (isToken!V && isToken!S)
    {
        if (!value.length || !sign.length) return false;

        static if (type == EVP_PKEY_EC)
        {
            if (sign.length != slen) return false;

            ubyte[71] sbuf;
            int bn_len = slen / 2;
            auto ec_sig_r = BN_bin2bn(sign.ptr, bn_len, null);
            auto ec_sig_s = BN_bin2bn(sign.ptr + bn_len, bn_len, null);
            if (!ec_sig_r || !ec_sig_s) return false;

            auto ec_sig = ECDSA_SIG_new();
            if (!ec_sig) onOutOfMemoryError;
            if (ECDSA_SIG_set0(ec_sig, ec_sig_r, ec_sig_s) != 1) return false;

            auto ch_slen = i2d_ECDSA_SIG(ec_sig, null);
            assert(ch_slen <= sbuf.length);
            auto p = &sbuf[0];
            ch_slen = i2d_ECDSA_SIG(ec_sig, &p);
            if (ch_slen == 0) return false;
            auto psig = &sbuf[0];
            auto siglen = ch_slen;
        }
        else
        {
            auto psig = sign.ptr;
            auto siglen = sign.length;
        }

        // Initialize the DigestVerify operation using evp algorithm
        if (EVP_DigestVerifyInit(mdctx, null, evp, null, pubkey) != 1)
            return false;

        if (EVP_DigestVerifyUpdate(mdctx, value.ptr, value.length) != 1)
            return false;

        auto ret = EVP_DigestVerifyFinal(mdctx, psig, siglen);
        if (ret == -1)
        {
            version (assert) ERR_print_errors_fp(stderr);
            return false;
        }
        return ret == 1;
    }

    JWTAlgorithm signAlg() { return implAlg; }

    int sign(S, V)(auto ref S sink, auto ref V value)
    {
        return 0;
    }
}

unittest
{
    static assert(isValidator!HS256Handler);
    static assert(isSigner!HS256Handler);
    static assert(isValidator!ES256Handler);
    static assert(isSigner!ES256Handler);
}
