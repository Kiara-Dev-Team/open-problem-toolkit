#!/usr/bin/env julia

import Pkg
Pkg.activate(joinpath(@__DIR__, "..")); Pkg.instantiate()

include(joinpath(@__DIR__, "..", "src", "PQCValidator.jl"))
include(joinpath(@__DIR__, "..", "src", "HKDFHelpers.jl"))
include(joinpath(@__DIR__, "..", "src", "TLSProbe.jl"))
include(joinpath(@__DIR__, "..", "src", "TraceConsistency.jl"))
include(joinpath(@__DIR__, "..", "src", "ConfigLoader.jl"))
# Optional lab mode:
global lab_ok = false
try
    include(joinpath(@__DIR__, "..", "src", "OQS.jl"))
    include(joinpath(@__DIR__, "..", "src", "LabHarness.jl"))
    global lab_ok = true
catch err
    # liboqs not present; lab mode will be unavailable
end

using .PQCValidator
using .TLSProbe
using .TraceConsistency
using .ConfigLoader
if lab_ok; using .LabHarness; end
using DataFrames, PrettyTables, JSON3, Dates

# Load configuration
config = ConfigLoader.load_config()

# ---- tiny arg parser (env overrides also supported) ----
function getarg(flag::String, default::String)
    for (i,a) in enumerate(ARGS)
        if a == flag && i < length(ARGS); return ARGS[i+1]; end
        if startswith(a, flag*"="); return split(a,"=",limit=2)[2]; end
    end
    return get(ENV, replace(flag, "--"=>"PQC_") |> uppercase, default)
end

mode  = getarg("--mode", "external")            # external | lab
host  = getarg("--host", config.endpoint_host)
port  = parse(Int, getarg("--port", string(config.endpoint_port)))
sni   = getarg("--sni", config.endpoint_sni)
group = getarg("--group", config.tls_force_group_arg)
keylog= getarg("--keylog", "keylog.txt")
hash  = getarg("--hash", config.policy_hash)

acceptable_groups = String.(split(getarg("--acceptable", join(config.tls_acceptable_groups, ",")), ","))

# ---- run ----
j = PQCValidator.Judgment()
j.timestamp = string(Dates.now())
j.combiner  = config.policy_combiner
j.kem_param = config.policy_kem_param

if mode == "external"
    println(">> external probe against $host:$port (group hint: $group)")
    art = TLSProbe.openssl_probe(host, port; group_arg=group, sni=sni, keylog_path=keylog)
    j.endpoint = "$host:$port"
    j = TLSProbe.judge_external(art.stdout; acceptable_groups=acceptable_groups)
    j.endpoint = "$host:$port"
    TraceConsistency.judge_consistency!(j, keylog; hash=hash)
elseif mode == "lab"
    if !lab_ok
        println("Lab mode unavailable (liboqs not found).")
        exit(2)
    end
    println(">> lab harness (offline witness, ML-KEM-768 + X25519)")
    j = LabHarness.judge_lab(combiner="concat+kdf", hash=hash)
    j.endpoint = "lab-offline"
else
    println("Unknown --mode (use external | lab)")
    exit(2)
end

# ---- emit artifact ----
df = DataFrames.DataFrame([
    ("Verdict", j.pass ? "PASS" : "FAIL"),
    ("Endpoint", j.endpoint),
    ("TLS 1.3", string(j.tls13)),
    ("NamedGroup", isempty(j.named_group) ? "(n/a)" : j.named_group),
    ("KEM param", string(j.kem_param)),
    ("Combiner", j.combiner),
    ("Timestamp", j.timestamp)
], [:Field, :Value])
PrettyTables.pretty_table(df)

open("audit.json","w") do io
    write(io, PQCValidator.to_json(j))
end
println("Saved artifact: audit.json")
exit(j.pass ? 0 : 1)
