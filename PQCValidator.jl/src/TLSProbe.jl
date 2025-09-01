module TLSProbe

using ..PQCValidator: Judgment, pass!, fail!, finalize!

# Run OpenSSL s_client with oqsprovider (installed on system)
function openssl_probe(host::String, port::Int; group_arg::String="X25519:MLKEM768",
                       sni::String=host, keylog_path::String="")
    cmd = `openssl s_client -connect $(host):$(port) -tls1_3 -servername $(sni) \
           -groups $(group_arg) -quiet`
    if !isempty(keylog_path)
        cmd = setenv(cmd, "SSLKEYLOGFILE" => keylog_path)
    end
    try
        process = run(pipeline(cmd, stdin=devnull), wait=false)
        out = read(process.out, String)
        wait(process)
        if process.exitcode != 0
            return (stdout="ERROR: OpenSSL exited with code $(process.exitcode)", keylog=keylog_path, exitcode=process.exitcode)
        end
        return (stdout=out, keylog=keylog_path, exitcode=0)
    catch e
        error_msg = if isa(e, ProcessFailedException)
            "OpenSSL process failed: exit code $(e.procs[1].exitcode)"
        elseif isa(e, SystemError)
            "System error running OpenSSL: $(e.msg)"
        else
            "OpenSSL command failed: $e"
        end
        return (stdout="ERROR: $error_msg", keylog=keylog_path, exitcode=-1)
    end
end

# Heuristic parse: TLS1.3 and a hybrid group alias
function judge_external(stdout::String; acceptable_groups::Vector{String})
    j = Judgment()
    j.tls13 = occursin("TLSv1.3", stdout) || occursin("TLSv1.3,", stdout)
    if j.tls13; pass!(j, "TLS 1.3 negotiated") else fail!(j, "TLS 1.3 not negotiated") end

    for g in acceptable_groups
        if occursin(g, stdout)
            j.named_group = g
            break
        end
    end
    if isempty(j.named_group)
        fail!(j, "No acceptable hybrid NamedGroup found in transcript")
    else
        pass!(j, "Hybrid NamedGroup present: " * j.named_group)
    end

    j.artifacts["transcript"] = stdout
    finalize!(j)
end

export openssl_probe, judge_external

end
