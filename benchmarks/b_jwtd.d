#!/usr/bin/env dub
/+ dub.sdl:
    name "bench_jwtd"
    targetType "executable"

    dependency "jwtd" version="~>0.4.6"

    configuration "phobos" {
        targetName "bench_jwtd_phobos"
        subConfiguration "jwtd" "phobos"
    }

    configuration "openssl" {
        targetName "bench_jwtd_openssl"
        subConfiguration "jwtd" "openssl-1.1"
    }

    configuration "botan" {
        targetName "bench_jwtd_botan"
        subConfiguration "jwtd" "botan"
    }
+/

module bench.jwtd;
import core.memory;
import std.conv;
import std.datetime.stopwatch;
import std.json;
import std.stdio;
import jwtd.jwt;

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

        if (args[1] == "val") return validate(cycles, args[4], args[5]);
        else if (args[1] == "dec") return decode(cycles, args[4], args[5]);
        else if (args[1] == "enc") return encode(cycles, alg, args[4], args[5]);
    }

    writeln("Invalid command: ", args[1]);
    return 1;
}

int validate(size_t cycles, string token, string secret)
{
    bool res;
    foreach (_; 0..cycles)
        res = verify(token, secret);
    writeln(res);
    return 0;
}

int decode(size_t cycles, string token, string secret)
{
    JSONValue res;
    foreach (_; 0..cycles)
        res = jwtd.jwt.decode(token, secret);
    writeln(res);
    return 0;
}

int encode(size_t cycles, JWTAlgorithm alg, string payload, string secret)
{
    string res;
    JSONValue pay = parseJSON(payload);
    foreach (_; 0..cycles)
        res = jwtd.jwt.encode(pay, secret);
    writeln(res);
    return 0;
}
