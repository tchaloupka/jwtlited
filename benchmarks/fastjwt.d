#!/usr/bin/env dub
/+ dub.sdl:
    name "bench_fastjwt"
    dependency "fastjwt" version="~>1.1.1"
+/

module bench.fastjwt;
import core.memory;
import std.conv;
import std.datetime.stopwatch;
import std.json;
import std.stdio;
import fastjwt.jwt;
import stringbuffer;

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

        if (args[1] == "val") return validate(cycles, alg, args[4], args[5]);
        else if (args[1] == "dec") return decode(cycles, alg, args[4], args[5]);
        else if (args[1] == "enc") return encode(cycles, alg, args[4], args[5]);
    }

    writeln("Invalid command: ", args[1]);
    return 1;
}

int validate(size_t cycles, JWTAlgorithm alg, string token, string secret)
{
    StringBuffer head, pay;
    bool ret;
    foreach (_; 0..cycles)
        ret = 0 == decodeJWTToken(token, secret, alg, head, pay);
    writeln(ret);
    return 0;
}

int decode(size_t cycles, JWTAlgorithm alg, string token, string secret)
{
    StringBuffer head, pay;
    foreach (_; 0..cycles)
    {
        head.removeAll();
        pay.removeAll();
        decodeJWTToken(token, secret, alg, head, pay);
    }
    writeln(pay.getData());
    return 0;
}

int encode(size_t cycles, JWTAlgorithm alg, string payload, string secret)
{
    import vibe.data.json;
    StringBuffer token;
    auto jpay = parseJson(payload);
    foreach (_; 0..cycles)
    {
        token.removeAll();
        token.encodeJWTToken(alg, secret, jpay);
    }
    writeln(token.getData());
    return 0;
}
