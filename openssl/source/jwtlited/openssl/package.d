module jwtlited.openssl;

public import jwtlited;
version (assert) import core.stdc.stdio;

import deimos.openssl.ec;
import deimos.openssl.err;
import deimos.openssl.evp;
import deimos.openssl.hmac;
import deimos.openssl.pem;
import deimos.openssl.sha;

// some missing symbols
extern(C) nothrow @nogc
{
    void EVP_MD_CTX_free(EVP_MD_CTX* ctx);
    EVP_MD_CTX* EVP_MD_CTX_new();
    int ECDSA_SIG_set0(ECDSA_SIG* sig, BIGNUM* r, BIGNUM* s);
}

/**
 * Implementation of HS256, HS384 and HS512 signing algorithms.
 */
struct HMAC
{
    JWTAlgorithm alg() @safe pure nothrow @nogc inout
    {
        return this.alg_;
    }

    private
    {
        const(char)[] key;
        JWTAlgorithm alg_;
        HMAC_CTX ctx;
        ubyte[SHA512_DIGEST_LENGTH] sigBuf;
        const(EVP_MD)* evp;
        uint signLen;
    }

    @disable this(this);

    ~this() @trusted
    {
        HMAC_CTX_reset(&ctx);
    }

    bool loadKey(K)(K key, JWTAlgorithm alg = JWTAlgorithm.HS256) if (isToken!K)
    {
        assert(alg >= JWTAlgorithm.HS256 && alg <= JWTAlgorithm.HS512, "Invalid hashing algorithm provided");

        if (!key.length) return false;
        this.key = cast(const(char)[])key;
        this.alg_ = alg;

        auto ret = () @trusted
        {
            switch (alg)
            {
                case JWTAlgorithm.HS256:
                    evp = EVP_sha256();
                    signLen = SHA256_DIGEST_LENGTH;
                    break;
                case JWTAlgorithm.HS384:
                    evp = EVP_sha384();
                    signLen = SHA384_DIGEST_LENGTH;
                    break;
                case JWTAlgorithm.HS512:
                    evp = EVP_sha512();
                    signLen = SHA512_DIGEST_LENGTH;
                    break;
                default: assert(0);
            }

            HMAC_CTX_reset(&ctx);
            return HMAC_Init_ex(&ctx, this.key.ptr, cast(int)key.length, evp, null);
        }();
        if (!ret) return false;
        return true;
    }

    bool isValid(V, S)(V value, S sign) if (isToken!V && isToken!S)
    {
        if (!genSignature(value)) return false;
        return cast(const(ubyte)[])sign == sigBuf[0..signLen];
    }

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

        ret = HMAC_Final(&ctx, sigBuf.ptr, &signLen);
        if (!ret) return false;
        return true;
    }
}

/**
 * Implementation of ES256, ES384 and ES512 signing algorithms.
 */
struct ECDSA
{
    JWTAlgorithm alg() @safe pure nothrow @nogc inout
    {
        return this.alg_;
    }

    private
    {
        JWTAlgorithm alg_;
        int slen;
        int type;
        EVP_PKEY* pubkey;
        const(EVP_MD)* evp;
        EVP_MD_CTX* mdctx;
    }

    ~this() @trusted
    {
        if (pubkey) EVP_PKEY_free(pubkey);
        if (mdctx) EVP_MD_CTX_free(mdctx);
    }

    bool loadKey(K)(K key, JWTAlgorithm alg = JWTAlgorithm.ES256) @trusted if (isToken!K)
    {
        assert(alg >= JWTAlgorithm.ES256 && alg <= JWTAlgorithm.ES512, "Invalid hashing algorithm provided");

        if (!key.length) return false;

        this.alg_ = alg;
        switch (alg)
        {
            case JWTAlgorithm.ES256:
                evp = EVP_sha256();
                type = EVP_PKEY_EC;
                break;
            case JWTAlgorithm.ES384:
                evp = EVP_sha384();
                type = EVP_PKEY_EC;
                break;
            case JWTAlgorithm.ES512:
                evp = EVP_sha512();
                type = EVP_PKEY_EC;
                break;
            default: assert(0);
        }

        BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, cast(int)key.length);
        if (!bpo) return false;
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

        if (type == EVP_PKEY_EC)
        {
            // Get the actual ec_key
            auto ec_key = EVP_PKEY_get1_EC_KEY(pubkey);
            if (!ec_key) return false;
            auto degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));
            EC_KEY_free(ec_key);

            auto bn_len = (degree + 7) / 8;
            slen = bn_len * 2;
        }

        mdctx = EVP_MD_CTX_new();
        if (!mdctx) return false;

        return true;
    }

    bool loadPKey(K)(K key)
    {
        return false;
    }

    bool isValid(V, S)(V value, S sign) @trusted if (isToken!V && isToken!S)
    {
        if (!value.length || !sign.length) return false;

        auto psig = sign.ptr;
        auto siglen = sign.length;
        ubyte[71] sbuf;

        if (type == EVP_PKEY_EC)
        {
            if (sign.length != slen) return false;

            int bn_len = slen / 2;
            auto ec_sig_r = BN_bin2bn(sign.ptr, bn_len, null);
            auto ec_sig_s = BN_bin2bn(sign.ptr + bn_len, bn_len, null);
            if (!ec_sig_r || !ec_sig_s) return false;

            auto ec_sig = ECDSA_SIG_new();
            if (!ec_sig) return false;
            if (ECDSA_SIG_set0(ec_sig, ec_sig_r, ec_sig_s) != 1) return false;

            auto ch_slen = i2d_ECDSA_SIG(ec_sig, null);
            assert(ch_slen <= sbuf.length);
            auto p = &sbuf[0];
            ch_slen = i2d_ECDSA_SIG(ec_sig, &p);
            if (ch_slen == 0) return false;
            psig = &sbuf[0];
            siglen = ch_slen;
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

    int sign(S, V)(auto ref S sink, auto ref V value)
    {
        return 0;
    }
}

unittest
{
    static assert(isValidator!HMAC);
    static assert(isSigner!HMAC);
    static assert(isValidator!ECDSA);
    static assert(isSigner!ECDSA);
}
