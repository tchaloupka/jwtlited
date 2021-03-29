module jwtlited.gnutls;

public import jwtlited;
version (assert) import core.stdc.stdio;
import core.stdc.string : memcpy;
import bindbc.gnutls;

version (DYNAMIC_GNUTLS)
{
    shared static this()
    {
        import core.stdc.stdio;
        import loader = bindbc.loader.sharedlib;
        auto res = loadGnuTLS();
        if (res < GnuTLSSupport.gnutls_3_5_0)
        {
            fprintf(stderr, "Error loading GnuTLS: %d\n", res);
            foreach(info; loader.errors)
            {
                fprintf(stderr, "\t%s: %s\n", info.error, info.message);
            }
            assert(0, "Error loading GnuTLS");
        }
    }
}

alias HS256Handler = HMACImpl!(JWTAlgorithm.HS256);
alias HS384Handler = HMACImpl!(JWTAlgorithm.HS384);
alias HS512Handler = HMACImpl!(JWTAlgorithm.HS512);

/**
 * Implementation of HS256, HS384 and HS512 signing algorithms.
 */
private struct HMACImpl(JWTAlgorithm implAlg)
{
    static if (implAlg == JWTAlgorithm.HS256) enum signLen = 32;
    else static if (implAlg == JWTAlgorithm.HS384) enum signLen = 48;
    else static if (implAlg == JWTAlgorithm.HS512) enum signLen = 64;
    else static assert(0, "Unsupprted algorithm for HMAC implementation");

    private
    {
        const(char)[] key;
        gnutls_hmac_hd_t ctx;
        ubyte[signLen] sigBuf;
    }

    @disable this(this);

    ~this() @trusted
    {
        if (ctx) gnutls_hmac_deinit(ctx, null);
    }

    bool loadKey(K)(K key) if (isToken!K)
    {
        if (!key.length) return false;
        this.key = cast(const(char)[])key;

        immutable ret = () @trusted
        {
            static if (implAlg == JWTAlgorithm.HS256) alias alg = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA256;
            else static if (implAlg == JWTAlgorithm.HS384) alias alg = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA384;
            else static if (implAlg == JWTAlgorithm.HS512) alias alg = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA512;

            assert(signLen == gnutls_hmac_get_len(alg));
            return gnutls_hmac_init(&ctx, alg, this.key.ptr, key.length);
        }();
        assert(ctx);
        return ret == 0;
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
        import std.range : put;
        if (!genSignature(value)) return -1;
        put(sink, sigBuf[0..signLen]);
        return signLen;
    }

    private bool genSignature(V)(V value) @trusted
    {
        assert(key.length, "Secret key not set");
        if (!key.length || !value.length) return false;

        auto ret = gnutls_hmac(ctx, value.ptr, value.length);
        if (ret < 0) return false;

        gnutls_hmac_output(ctx, sigBuf.ptr);
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
        gnutls_x509_privkey_t x509key;
        gnutls_privkey_t privKey;
        gnutls_pubkey_t pubKey;

        import std.algorithm : among;
        static if (implAlg.among(JWTAlgorithm.ES256, JWTAlgorithm.ES384, JWTAlgorithm.ES512))
            enum pkAlg = gnutls_pk_algorithm_t.GNUTLS_PK_ECDSA;
        else static if (implAlg.among(JWTAlgorithm.RS256, JWTAlgorithm.RS384, JWTAlgorithm.RS512))
            enum pkAlg = gnutls_pk_algorithm_t.GNUTLS_PK_RSA;
        else static assert(0, "Unsupprted algorithm for PEM implementation");

        static if (implAlg == JWTAlgorithm.ES256) alias alg = gnutls_sign_algorithm_t.GNUTLS_SIGN_ECDSA_SHA256;
        else static if (implAlg == JWTAlgorithm.ES384) alias alg = gnutls_sign_algorithm_t.GNUTLS_SIGN_ECDSA_SHA384;
        else static if (implAlg == JWTAlgorithm.ES512) alias alg = gnutls_sign_algorithm_t.GNUTLS_SIGN_ECDSA_SHA512;
        else static if (implAlg == JWTAlgorithm.RS256) alias alg = gnutls_sign_algorithm_t.GNUTLS_SIGN_RSA_SHA256;
        else static if (implAlg == JWTAlgorithm.RS384) alias alg = gnutls_sign_algorithm_t.GNUTLS_SIGN_RSA_SHA384;
        else static if (implAlg == JWTAlgorithm.RS512) alias alg = gnutls_sign_algorithm_t.GNUTLS_SIGN_RSA_SHA512;
    }

    @disable this(this);

    ~this() @trusted
    {
        if (x509key) gnutls_x509_privkey_deinit(x509key);
        if (privKey) gnutls_privkey_deinit(privKey);
        if (pubKey) gnutls_pubkey_deinit(pubKey);
    }

    bool loadKey(K)(K key) @trusted if (isToken!K)
    {
        if (!key.length) return false;

        if (gnutls_pubkey_init(&pubKey)) return false;

        gnutls_datum_t cert_dat = gnutls_datum_t(cast(ubyte*)key.ptr, cast(uint)key.length);
        if (gnutls_pubkey_import(pubKey, &cert_dat, gnutls_x509_crt_fmt_t.GNUTLS_X509_FMT_PEM))
        {
            gnutls_pubkey_deinit(pubKey);
            pubKey = null;
            return false;
        }

        return true;
    }

    bool loadPKey(K)(K key) @trusted if (isToken!K)
    {
        if (gnutls_x509_privkey_init(&x509key)) return false;

        gnutls_datum_t keyData = gnutls_datum_t(cast(ubyte*)key.ptr, cast(uint)key.length);
        if (gnutls_x509_privkey_import(x509key, &keyData, gnutls_x509_crt_fmt_t.GNUTLS_X509_FMT_PEM))
            goto err;

        if (gnutls_privkey_init(&privKey)) goto err;
        if (gnutls_privkey_import_x509(privKey, x509key, 0)) goto err;
        if (pkAlg != gnutls_privkey_get_pk_algorithm(privKey, null)) goto err;

        return true;

        err:
            if (x509key) { gnutls_x509_privkey_deinit(x509key); x509key = null; }
            if (privKey) { gnutls_privkey_deinit(privKey); privKey = null; }
            return false;
    }

    bool isValidAlg(JWTAlgorithm alg) { return implAlg == alg; }

    bool isValid(V, S)(V value, S sign) @trusted if (isToken!V && isToken!S)
    {
        version (unittest) {} // no assert behavior is tested in unittest
        else assert(pubKey, "Public key not set");
        if (!value.length || !sign.length || !pubKey) return false;

        gnutls_datum_t data = gnutls_datum_t(cast(ubyte*)value.ptr, cast(uint)value.length);
        static if (pkAlg == gnutls_pk_algorithm_t.GNUTLS_PK_RSA)
        {
            gnutls_datum_t sig_dat = gnutls_datum_t(sign.ptr, cast(uint)sign.length);
            if (gnutls_pubkey_verify_data2(pubKey, alg, 0, &data, &sig_dat))
                return false;
        }
        else
        {
            // Rebuild signature using r and s extracted from sig

            gnutls_datum_t r, s;
            static if (implAlg == JWTAlgorithm.ES256)
            {
                if (sign.length != 64) return false;
                r.size = 32;
                r.data = sign.ptr;
                s.size = 32;
                s.data = sign.ptr + 32;
            }
            else static if (implAlg == JWTAlgorithm.ES384)
            {
                if (sign.length != 96) return false;
                r.size = 48;
                r.data = sign.ptr;
                s.size = 48;
                s.data = sign.ptr + 48;
            }
            else static if (implAlg == JWTAlgorithm.ES512)
            {
                if (sign.length != 132) return false;
                r.size = 66;
                r.data = sign.ptr;
                s.size = 66;
                s.data = sign.ptr + 66;
            }
            else static assert(0);

            gnutls_datum_t sig_dat;
            scope (exit)
            {
                if (sig_dat.data) gnutls_free(sig_dat.data);
            }

            if (gnutls_encode_rs_value(&sig_dat, &r, &s)) return false;
            if (gnutls_pubkey_verify_data2(pubKey, alg, 0, &data, &sig_dat)) return false;
        }
        return true;
    }

    JWTAlgorithm signAlg() { return implAlg; }

    int sign(S, V)(auto ref S sink, auto ref V value) @trusted
    {
        import std.range : put;

        version (unittest) {} // no assert behavior is tested in unittest
        else assert(privKey, "Private key not set");
        if (!value.length || !privKey) return -1;

        gnutls_datum_t body_dat = gnutls_datum_t(cast(ubyte*)value.ptr, cast(uint)value.length);
        gnutls_datum_t sig_dat;

        immutable ret = gnutls_privkey_sign_data2(privKey, alg, 0, &body_dat, &sig_dat);
        if (ret) return -1;
        scope (exit) gnutls_free(sig_dat.data);

        static if (pkAlg == gnutls_pk_algorithm_t.GNUTLS_PK_RSA)
        {
            put(sink, sig_dat.data[0..sig_dat.size]);
            return sig_dat.size;
        }
        else
        {
            gnutls_datum_t r, s;
            if (gnutls_decode_rs_value(&sig_dat, &r, &s)) return -1;
            scope (exit)
            {
                gnutls_free(r.data);
                gnutls_free(s.data);
            }

            static if (implAlg == JWTAlgorithm.ES256) enum adj = 32;
            else static if (implAlg == JWTAlgorithm.ES384) enum adj = 48;
            else static if (implAlg == JWTAlgorithm.ES512) enum adj = 66;

            int r_padding, s_padding, r_out_padding, s_out_padding;
            size_t out_size;

            if (r.size > adj) r_padding = r.size - adj;
            else if (r.size < adj) r_out_padding = adj - r.size;

            if (s.size > adj) s_padding = s.size - adj;
            else if (s.size < adj) s_out_padding = adj - s.size;

            out_size = adj << 1;
            ubyte[512] buf;
            assert(buf.length >= out_size);

            memcpy(buf.ptr + r_out_padding, r.data + r_padding, r.size - r_padding);
            memcpy(
                buf.ptr + (r.size - r_padding + r_out_padding) + s_out_padding,
                s.data + s_padding,
                s.size - s_padding
            );

            assert((r.size - r_padding + r_out_padding) + (s.size - s_padding + s_out_padding) == out_size);
            put(sink, buf[0..out_size]);
            return (r.size - r_padding + r_out_padding) + (s.size - s_padding + s_out_padding);
        }
    }
}

version (unittest) import jwtlited.tests;

@("GnuTLS tests")
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

