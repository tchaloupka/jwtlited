#!/usr/bin/env dub
/+ dub.sdl:
    name "runner"
    dependency "jwtlited:openssl" path="../"
+/

import std.algorithm;
import std.array;
import std.conv;
import std.json;
import std.file;
import std.format;
import std.path;
import std.process;
import std.stdio;
import std.string;
import jwtlited.openssl;

static immutable HMAC_SECRET = ["foobarbaz123456"];
static immutable RSA_SECRET = [
    `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0hZf4ct1tvPkcqM7826L89TwCPBhuycWMn3xT+4MLeUqe51F
LMSm1VK6k+Ew8jrmQ9T9tOtp2vRJFEhoK/WVAb44Sg0PuX9zDLw8ncgW9jON4q6X
m9MeJNC2Mb5ogwc72S+kQWNWi3nNR9xrCXmczHfoolVC9/lnU0T+Tp7kj4MZNmSC
Cx0eACHpkZV5306TAs+FSlOpKgTL9Wazf1i7teTddkhD5Csm/OE5gBqdAQDqO/8q
aKDpmYJTdrjM8RebBq9eTuc5sp7zzIGH2hjveiBG7+/83dDgLwW5IUV1+EB/VqSx
jrlurQcH38zYfmXV65QCToJXbF5X3asUluSu9wIDAQABAoIBAQCfXV2qeJ55BBW9
aFnn1WnQsyzKex6Hy6So9KSDD36pqfdKAgkhZqNvmuvxlZd9iHR37C/wd8u6zihJ
fIuZHRfFVLh6Y+ITwrxRYtFQlyHj7UOqOurCx6lMIA61OU0qZ+hcXilpeKOD9gdk
ha2kaF4rNKKB0c+VL9nTbrjChwG2YkneqROL7KyszVHAumU9sZUtaYsxKvwALwZi
7GStXCa8yFb0AXuTANWzVQt5QsFvIO5GpXjQrmYJM36pwzKNVKBFCqrMrRoQhuwe
UfXOI/VF1tUM9BhZ78R/ccxBGyklQCJt2wO1GqnWKH1lUDHUTDv//V3kI4TF8Tba
lEn4l8fhAoGBAPYIVsjDZdi7LTnkXENlUTf+VvWGwM7Upb7QK0LK6rZkJrFeiLfT
vPd4TDEcNHcWVKz+dZubJ5m1rC8hh4IUsQv5CcZdcQuJ/dINZyPRyNkNU4O+kDmf
50xemRMm9JwpvJfSRsIzoFizzwNsvYeJpQm5ZbGHdVxM1kQBt0P05Hk/AoGBANqZ
PWLTcKh942GXDzlr6sg4067neYg5fKMeUU6QsDN5Zf6MmPBNDDVd5+oMTjxRQiSW
Q4SIqR2ssDDuowBGBSoAirQyTdiQ/lVo4/h9oQJX2fDEQvMsPSaby6MBzl9kSSPz
fBeqSM5fCt6HpkLvzIwS6AlQ4lFzj3fU7tZ3vuRJAoGAGr6FUIWNCKYwIF7meJ0G
2yNWqJHhW5pZ+gf+69/K69CvNBCmo/TsUapN/fim61sOEVAH0MZo45iQAv+OD2HY
bQjBO0LlCvARG0hBse8X+iAst+F7JAhxyCdwVFijtmYDDi3ZazrZb0r8cc7cO2OH
ASuaFlY3N7VShUn6dfSk8VkCgYB0RawUI9k5lfRbFUlgxpkUNL3Lu422OrWj4d1n
h6hhSMJKmihDMQg8Xp2brT3z8VjYMyDonvQtN4xkCpqi65uVksI0RMmJVt4hOfCA
XPpGT8o5uXrO84n3PkkbhDtsG+CXgcxQnh+pvX3/jXGPCxPmsavAQMiQgIIgQB9l
7j2YGQKBgERkwz7s29PN9jg/9D0UGynxhkvJhIo8EcN42/lrnr4MziHxIHN5CwBv
oNHVKMZXklzzZ7X2jZcqY5UbTIOwiDonwmjfch8SSHt4L50MIzaCrxzDaEQ//zd6
qT7bwBrcVfn7JUE8RRk5qEn5Z81Z/4AciYBFbsOowA/1NDhLoCZ5
-----END RSA PRIVATE KEY-----`,
    `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0hZf4ct1tvPkcqM7826L
89TwCPBhuycWMn3xT+4MLeUqe51FLMSm1VK6k+Ew8jrmQ9T9tOtp2vRJFEhoK/WV
Ab44Sg0PuX9zDLw8ncgW9jON4q6Xm9MeJNC2Mb5ogwc72S+kQWNWi3nNR9xrCXmc
zHfoolVC9/lnU0T+Tp7kj4MZNmSCCx0eACHpkZV5306TAs+FSlOpKgTL9Wazf1i7
teTddkhD5Csm/OE5gBqdAQDqO/8qaKDpmYJTdrjM8RebBq9eTuc5sp7zzIGH2hjv
eiBG7+/83dDgLwW5IUV1+EB/VqSxjrlurQcH38zYfmXV65QCToJXbF5X3asUluSu
9wIDAQAB
-----END PUBLIC KEY-----`
];

static immutable ECDSA_SECRET = [
    `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILvM6E7mLOdndALDyFc3sOgUTb6iVjgwRBtBwYZngSuwoAoGCCqGSM49
AwEHoUQDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBkNGyQ+P4bc/RmNEq1NpsogiMB
5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==
-----END EC PRIVATE KEY-----`,
    `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBk
NGyQ+P4bc/RmNEq1NpsogiMB5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==
-----END PUBLIC KEY-----`
];
enum PAYLOAD = `{"sub":"1234567890","name":"John Doe","iat":1516239022}`;
enum CYCLES = 500_000;

int main()
{
    // get benchmarks
    Bench[] benchmarks = dirEntries("", "bench_*", SpanMode.shallow)
        .filter!(a => a.name.getAttributes() & octal!700)
        .map!(a => Bench(
            a.name,
            a.name.baseName["bench_".length..$].replace('_', ' '),
            (cast(double)a.name.getSize()) / 1024 / 1024 // in MB
        ))
        .array;
    benchmarks.sort!((a,b) => a.name < b.name);

    if (!benchmarks.length)
    {
        writeln("No executable benchmarks found");
        return 1;
    }

    Appender!string sizes;
    foreach (ref b; benchmarks)
    {
        sizes.formattedWrite!`"%s"`(b.name);
        sizes.formattedWrite!" %s\n"(b.size);
    }

    writeln("Sizes:");
    writeln(sizes.data);

    genChart("sizes", "size [MB]", sizes.data, ["size"]);

    // benchmark HS256
    char[512] buf;
    HS256Handler hsenc;
    hsenc.loadKey(HMAC_SECRET[0]);
    auto len = hsenc.encode(buf[], PAYLOAD);
    assert(len > 0, "Failed to encode token");
    benchmarks.evaluate(CYCLES, "HS256", PAYLOAD, HMAC_SECRET, buf[0..len]);

    // benchmark RS256
    RS256Handler rsenc;
    rsenc.loadPKey(RSA_SECRET[0]);
    len = rsenc.encode(buf[], PAYLOAD);
    assert(len > 0, "Failed to encode token");
    benchmarks.evaluate(CYCLES/10, "RS256", PAYLOAD, RSA_SECRET, buf[0..len]);

    // benchmark ES256
    ES256Handler esenc;
    esenc.loadPKey(ECDSA_SECRET[0]);
    len = esenc.encode(buf[], PAYLOAD);
    assert(len > 0, "Failed to encode token");
    benchmarks.evaluate(CYCLES/10, "ES256", PAYLOAD, ECDSA_SECRET, buf[0..len]);

    return 0;
}

void evaluate(Bench[] benchmarks, int cycles, string alg, string pay, in string[] secret, const(char)[] tok)
{
    struct BenchRes
    {
        size_t colSize;
        string name;
        string[3] val;
    }

    static dumpRes(BenchRes[] res)
    {
        import std.range : repeat;
        write("|     |");
        foreach (r; res)
            write(' '.repeat(r.colSize-r.name.length+1), r.name, " |");
        write("\n|:---:|");
        foreach (r; res)
            write(' ', '-'.repeat(r.colSize), ":|");
        write("\n| val |");
        foreach (r; res)
            write(' '.repeat(r.colSize-r.val[0].length+1), r.val[0], " |");
        write("\n| dec |");
        foreach (r; res)
            write(' '.repeat(r.colSize-r.val[1].length+1), r.val[1], " |");
        write("\n| enc |");
        foreach (r; res)
            write(' '.repeat(r.colSize-r.val[2].length+1), r.val[2], " |");
        writeln();
    }

    auto bench = benchmarks.dup;

    writefln("Benchmarking %s, token: %s", alg, tok);
    foreach (ref b; bench)
    {
        if (!runBench!(What.val)(b, cycles, alg, tok, secret)) { b.ignore = true; continue; }
        if (!runBench!(What.dec)(b, cycles, alg, tok, secret)) { b.ignore = true; continue; }
        if (!runBench!(What.enc)(b, cycles, alg, pay, secret)) { b.ignore = true; continue; }
    }

    Appender!(BenchRes[]) gcres;
    Appender!(BenchRes[]) speedres;
    foreach (ref b; bench.filter!(a => !a.ignore))
    {
        BenchRes gc, sp;
        gc.name = sp.name = b.name;
        gc.val[0] = format!"%s"(b.valGC);
        gc.val[1] = format!"%s"(b.decGC);
        gc.val[2] = format!"%s"(b.encGC);
        gc.colSize = max(gc.name.length, gc.val[0].length, gc.val[1].length, gc.val[2].length);
        gcres ~= gc;

        sp.val[0] = format!"%s"(b.val);
        sp.val[1] = format!"%s"(b.dec);
        sp.val[2] = format!"%s"(b.enc);
        sp.colSize = max(sp.name.length, sp.val[0].length, sp.val[1].length, sp.val[2].length);
        speedres ~= sp;
    }

    writeln;
    writeln("GC usage:");
    dumpRes(gcres.data);

    writeln;
    writeln("Speed:");
    dumpRes(speedres.data);

    // charts
    Appender!string[3] speed;
    Appender!string[3] gcusage;

    gcusage[0] ~= "val";
    gcusage[1] ~= "dec";
    gcusage[2] ~= "enc";
    speed[0]   ~= "val";
    speed[1]   ~= "dec";
    speed[2]   ~= "enc";
    foreach (ref b; bench.filter!(a => !a.ignore))
    {
        gcusage[0].formattedWrite!" %s"(b.valGC);
        gcusage[1].formattedWrite!" %s"(b.decGC);
        gcusage[2].formattedWrite!" %s"(b.encGC);

        speed[0].formattedWrite!" %s"(b.val);
        speed[1].formattedWrite!" %s"(b.dec);
        speed[2].formattedWrite!" %s"(b.enc);
    }

    auto names = bench.filter!(a => !a.ignore).map!(a => a.name).array;

    genChart(format!"gcusage_%s"(alg.toLower), "GC memory [MB]", gcusage[].map!(a => a.data).joiner("\n").text, names);
    genChart(format!"speed_%s"(alg.toLower), "tokens per second", speed[].map!(a => a.data).joiner("\n").text, names);
}

void genChart(string name, string yAxisName, string data, string[] colNames)
{
    Appender!string chart;
    chart.formattedWrite!`set output "results/%s.png"
set terminal pngcairo font "arial,10" size 1280,720
set style data histogram
set style histogram cluster gap 1
set style fill solid
set boxwidth 0.9
set xtics format ""
set yrange [0:*]
set grid ytics`(name);
    chart ~= "\n";
    chart.formattedWrite!`set ylabel "%s"`(yAxisName);
    chart ~= "\n$data << EOD\n";

    assert(colNames.length);
    chart ~= data;
    chart ~= "\nEOD\n";
    chart.formattedWrite!`plot $data using 2:xtic(1) t "%s"`(colNames[0]);
    foreach (i, n; colNames[1..$])
        chart.formattedWrite!`,'' using %d t "%s"`(i+3, n);

    // writeln(chart.data);

    auto gp = pipeProcess("gnuplot", Redirect.stdin | Redirect.stderrToStdout);
    gp.stdin.writeln(chart.data);
    gp.stdin.flush();
    gp.stdin.close();
    auto ret = gp.pid.wait();
    if (ret)
    {
        writeln("Error generating chart:");
        foreach (line; gp.stdout.byLine) writeln(line);
    }
}

enum What { val, dec, enc }

bool runBench(What what)(ref Bench b, int cycles, string alg, const(char)[] val, in string[] secret)
{
    static if (what == What.val) enum w = "val";
    else static if (what == What.dec) enum w = "dec";
    else enum w = "enc";

    static if (what != What.enc) {
        typeof(execute("")) ret;
        if (secret.length > 1)
            ret = execute([buildNormalizedPath(getcwd, b.path), w, cycles.to!string, alg, val, secret[1]]);
        else
            ret = execute([buildNormalizedPath(getcwd, b.path), w, cycles.to!string, alg, val, secret[0]]);
    }
    else
        auto ret = execute([buildNormalizedPath(getcwd, b.path), w, cycles.to!string, alg, val, secret[0]]);

    auto tmp = ret.output.splitLines;
    if (ret.status != 0) { writefln("Benchmark %s failed: %s", b.name, tmp.length ? tmp[0] : null); return false; }
    if (tmp.length != 3) { writefln("Unexpected benchmark %s result: %s", b.name, ret.output); return false; }

    bool validRes;
    static if (what == What.val) validRes = tmp[0] == "true";
    else static if (what == What.dec)
    {
        try validRes = parseJSON(tmp[0]) == parseJSON(PAYLOAD);
        catch (Exception ex) {}
    }
    else
    {
        if (alg == "HS256")
        {
            HS256Handler v;
            v.loadKey(secret[0]);
            validRes = v.validate(tmp[0]);
        }
        else if (alg == "RS256")
        {
            RS256Handler v;
            v.loadKey(secret[1]);
            validRes = v.validate(tmp[0]);
        }
        else if (alg == "ES256")
        {
            ES256Handler v;
            v.loadKey(secret[1]);
            validRes = v.validate(tmp[0]);
        }
        else assert(0, "Not implemented");
    }

    if (!validRes) { writefln("Invalid result from benchmark %s: %s", b.name, tmp[0]); return false; }

    size_t ms;
    try ms = tmp[1].to!size_t;
    catch (Exception ex) { writefln("Invalid duration from benchmark %s: %s", b.name, tmp[1]); return false; }

    immutable tps = 1_000 * cycles / ms;

    double gc;
    try gc = tmp[2].to!size_t;
    catch (Exception ex) { writefln("Invalid duration from benchmark %s: %s", b.name, tmp[1]); return false; }
    gc = gc / 1024 / 1024; // convert to MB

    static if (what == What.val) { b.val = tps; b.valGC = gc; }
    else static if (what == What.dec) { b.dec = tps; b.decGC = gc; }
    else { b.enc = tps; b.encGC = gc; }
    return true;
}

struct Bench
{
    string path;
    string name;
    double size;
    size_t val, dec, enc;
    double valGC, decGC, encGC;
    bool ignore;
}
