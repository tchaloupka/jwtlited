module jwtlited.openssl.tests;

version (unittest):

import jwtlited.openssl;
import jwtlited.tests;

@("JWTAlgorithm.none")
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

    import core.memory : GC;
    import std.algorithm : canFind, filter;

    immutable pre = () @trusted { return GC.stats(); }();

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
                case HS256: eval!HS256Handler(tc); break;
                case HS384: eval!HS384Handler(tc); break;
                case HS512: eval!HS512Handler(tc); break;

                case RS256:
                case RS384:
                case RS512:
                    break;

                case ES256: eval!ES256Handler(tc); break;
                case ES384: eval!ES384Handler(tc); break;
                case ES512: eval!ES512Handler(tc); break;
            }
        }
    }

    assert((() @trusted { return GC.stats().usedSize; }() - pre.usedSize) == 0); // check for no GC allocations
}
