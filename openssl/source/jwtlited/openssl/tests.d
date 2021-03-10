module jwtlited.openssl.tests;

version (unittest):

import jwtlited.openssl;
import jwtlited.tests;

@("JWTAlgorithm.none")
@safe unittest
{
    import core.memory : GC;
    import std.algorithm : canFind, filter;

    auto pre = () @trusted { return GC.stats(); }();

    with (JWTAlgorithm)
    {
        static immutable testAlgs = [
            HS256, HS384, HS512,
            // RS256, RS384, RS512,
            ES256, ES384, ES512
        ];

        foreach (tc; testCases.filter!(a => testAlgs.canFind(a.alg)))
        {
            final switch (tc.alg)
            {
                case none: assert(0);
                case HS256:
                case HS384:
                case HS512:
                    HMAC k;
                    assert(k.loadKey(tc.key, tc.alg) == !!(tc.valid & Valid.key));
                    evalTest(k, tc);
                    break;

                case RS256:
                case RS384:
                case RS512:
                    break;

                case ES256:
                case ES384:
                case ES512:
                    ECDSA k;
                    assert(k.loadKey(tc.key, tc.alg) == !!(tc.valid & Valid.key));
                    evalTest(k, tc);
                    break;
            }
        }
    }

    assert((() @trusted { return GC.stats().usedSize; }() - pre.usedSize) == 0); // check for no GC allocations
}
