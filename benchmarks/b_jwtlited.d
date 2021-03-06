#!/usr/bin/env dub
/+ dub.sdl:
    name "bench_jwtlited"
    targetType "executable"

    configuration "openssl" {
        targetName "bench_jwtlited_openssl"
        dependency "jwtlited:openssl" path="../"
        versions "USE_OPENSSL"
    }

    configuration "phobos" {
        targetName "bench_jwtlited_phobos"
        dependency "jwtlited:phobos" path="../"
        versions "USE_PHOBOS"
    }

    configuration "gnutls" {
        targetName "bench_jwtlited_gnutls"
        dependency "jwtlited:gnutls" path="../"
        versions "USE_GNUTLS"
    }
+/

module bench.jwtlited;
import core.memory;
import std.array;
import std.conv;
import std.datetime.stopwatch;
import std.stdio;
version (USE_OPENSSL) import jwtlited.openssl;
else version (USE_PHOBOS) import jwtlited.phobos;
else version (USE_GNUTLS) import jwtlited.gnutls;

int main(string[] args)
{
    // args: enc/dec/val, cycle count, alg, token/payload, signature
    // output:
    //   payload/token/true
    //   msecs taken
    //   GC used bytes

    if (args.length != 6) { writeln("Invalid args"); return 1; }
    size_t cycles = args[2].to!size_t;

    JWTAlgorithm alg = args[3].to!JWTAlgorithm;

    {
        StopWatch sw;
        sw.start();
        immutable prevAllocated = GC.allocatedInCurrentThread;
        scope (exit)
        {
            sw.stop();
            writeln(sw.peek.total!"msecs");
            writeln(GC.allocatedInCurrentThread - prevAllocated);
        }

        switch (alg)
        {
            case JWTAlgorithm.HS256:
                HS256Handler h;
                if (!h.loadKey(args[5])) { writeln("Problem loading secret"); return 1; }
                if (args[1] == "val") return h.validate(cycles, args[4]);
                else if (args[1] == "dec") return h.decode(cycles, args[4]);
                else if (args[1] == "enc") return h.encode(cycles, args[4]);
                break;
            case JWTAlgorithm.RS256:
                version (USE_PHOBOS) {}
                else
                {
                    RS256Handler h;
                    if (args[1] == "enc") {
                        if (!h.loadPKey(args[5])) { writeln("Problem loading secret"); return 1; }
                    } else {
                        if (!h.loadKey(args[5])) { writeln("Problem loading secret"); return 1; }
                    }
                    if (args[1] == "val") return h.validate(cycles, args[4]);
                    else if (args[1] == "dec") return h.decode(cycles, args[4]);
                    else if (args[1] == "enc") return h.encode(cycles, args[4]);
                    break;
                }
            case JWTAlgorithm.ES256:
                version (USE_PHOBOS) {}
                else
                {
                    ES256Handler h;
                    if (args[1] == "enc") {
                        if (!h.loadPKey(args[5])) { writeln("Problem loading secret"); return 1; }
                    } else {
                        if (!h.loadKey(args[5])) { writeln("Problem loading secret"); return 1; }
                    }
                    if (args[1] == "val") return h.validate(cycles, args[4]);
                    else if (args[1] == "dec") return h.decode(cycles, args[4]);
                    else if (args[1] == "enc") return h.encode(cycles, args[4]);
                    break;
                }
            default: writeln("Unsupported algorithm"); return 1;
        }
    }

    writeln("Invalid command: ", args[1]);
    return 1;
}

int validate(Handler)(ref Handler h, size_t cycles, string token)
{
    bool res;
    foreach (_; 0..cycles)
        res = jwtlited.validate(h, token);
    writeln(res);
    return 0;
}

int decode(Handler)(ref Handler h, size_t cycles, string token)
{
    ubyte[512] res;
    foreach (_; 0..cycles)
    {
        if (!jwtlited.decode(h, token, res[])) {
            writeln("Failed to decode token");
            return 1;
        }
    }
    import core.stdc.string;
    writeln(cast(char[])res[0..strlen(cast(const(char)*)res.ptr)]);
    return 0;
}

int encode(Handler)(ref Handler h, size_t cycles, string pay)
{
    char[512] buf;
    int len;
    foreach (_; 0..cycles)
        len = jwtlited.encode(h, buf[], pay);
    writeln(buf[0..len]);
    return 0;
}
