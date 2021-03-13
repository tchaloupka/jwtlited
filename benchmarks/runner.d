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

enum HMAC_SECRET = "foobarbaz123456";
enum PAYLOAD = `{"sub":"1234567890","name":"John Doe","iat":1516239022}`;
enum CYCLES = 500_000;

int main()
{
    // get benchmarks
    auto benchmarks = dirEntries("", "bench_*", SpanMode.shallow)
        .filter!(a => a.name.getAttributes() & octal!700)
        .map!(a => Bench(
            a.name,
            a.name.baseName["bench_".length..$].replace('_', ' '),
            (cast(double)a.name.getSize()) / 1024 / 1024 // in MB
        ))
        .array
        .sort!((a,b) => a.name < b.name);

    if (!benchmarks.length)
    {
        writeln("No executable benchmarks found");
        return 1;
    }

    // generate HS256 signed token
    char[512] buf;
    HS256Handler enc;
    enc.loadKey(HMAC_SECRET);
    auto len = enc.encode(buf[], PAYLOAD);
    assert(len > 0, "Failed to encode token");

    writeln("Benchmarking HS256, token: ", buf[0..len]);
    JSONValue jsonPayload = parseJSON(PAYLOAD); // some libs doesn't return parsed claims in the same order
    foreach (ref b; benchmarks)
    {
        bench!(What.val)(b, "HS256", buf[0..len], HMAC_SECRET);
        bench!(What.dec)(b, "HS256", buf[0..len], HMAC_SECRET);
        bench!(What.enc)(b, "HS256", PAYLOAD, HMAC_SECRET);
    }

    Appender!string sizes;
    Appender!string[3] gcusage;
    Appender!string[3] speed;
    foreach (ref b; benchmarks)
    {
        sizes.formattedWrite!`"%s"`(b.name);
        sizes.formattedWrite!" %s\n"(b.size);
    }

    gcusage[0] ~= "val"; speed[0] ~= "val";
    gcusage[1] ~= "dec"; speed[1] ~= "dec";
    gcusage[2] ~= "enc"; speed[2] ~= "enc";
    foreach (ref b; benchmarks)
    {
        gcusage[0].formattedWrite!" %s"(b.valGC);
        gcusage[1].formattedWrite!" %s"(b.decGC);
        gcusage[2].formattedWrite!" %s"(b.encGC);

        speed[0].formattedWrite!" %s"(b.val);
        speed[1].formattedWrite!" %s"(b.dec);
        speed[2].formattedWrite!" %s"(b.enc);
    }

    writeln("Sizes:");
    writeln(sizes.data);

    writeln;
    writeln("GC usage:");
    foreach (ref a; gcusage) writeln(a.data);

    writeln;
    writeln("Speed:");
    foreach (ref a; speed) writeln(a.data);

    auto names = benchmarks.map!(a => a.name).array;
    genChart("sizes", "size [MB]", sizes.data, ["size"]);
    genChart("gcusage", "GC memory [MB]", gcusage[].map!(a => a.data).joiner("\n").text, names);
    genChart("speed", "tokens per second", speed[].map!(a => a.data).joiner("\n").text, names);

    return 0;
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

void bench(What what)(ref Bench b, string alg, const(char)[] val, string secret)
{
    static if (what == What.val) enum w = "val";
    else static if (what == What.dec) enum w = "dec";
    else enum w = "enc";

    auto ret = execute([buildNormalizedPath(getcwd, b.path), w, CYCLES.to!string, alg, val, secret]);
    if (ret.status != 0) { writefln("Benchmark %s failed: %s", b.name, ret.output); return; }

    auto tmp = ret.output.splitLines;
    if (tmp.length != 3) { writefln("Unexpected benchmark %s result: %s", b.name, ret.output); return; }

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
            v.loadKey(secret);
            validRes = v.validate(tmp[0]);
        }
        else assert(0, "Not implemented");
    }

    if (!validRes) { writefln("Invalid result from benchmark %s: %s", b.name, tmp[0]); return; }

    size_t ms;
    try ms = tmp[1].to!size_t;
    catch (Exception ex) { writefln("Invalid duration from benchmark %s: %s", b.name, tmp[1]); return; }

    immutable tps = 1_000 * CYCLES / ms;

    double gc;
    try gc = tmp[2].to!size_t;
    catch (Exception ex) { writefln("Invalid duration from benchmark %s: %s", b.name, tmp[1]); return; }
    gc = gc / 1024 / 1024; // convert to MB

    static if (what == What.val) { b.val = tps; b.valGC = gc; }
    else static if (what == What.dec) { b.dec = tps; b.decGC = gc; }
    else { b.enc = tps; b.encGC = gc; }
}

struct Bench
{
    string path;
    string name;
    double size;
    size_t val, dec, enc;
    double valGC, decGC, encGC;
}
