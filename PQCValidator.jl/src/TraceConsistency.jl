module TraceConsistency

using ..PQCValidator: Judgment, pass!, fail!

using ..HKDFHelpers

# Small helpers
function hex2bytes(s::AbstractString)
    h = replace(lowercase(s), r"[^0-9a-f]" => "")
    @assert iseven(length(h)) "hex length must be even"
    out = Vector{UInt8}(undef, div(length(h),2))
    @inbounds for i in 1:length(out)
        out[i] = parse(UInt8, h[2i-1:2i], base=16)
    end
    out
end

function parse_keylog(path::String)
    C = nothing; S = nothing
    isfile(path) || return (nothing, nothing)
    for ln in eachline(path)
        sp = split(ln)
        length(sp) >= 3 || continue
        tag = sp[1]; val = sp[end]
        if tag == "CLIENT_HANDSHAKE_TRAFFIC_SECRET"; C = hex2bytes(val); end
        if tag == "SERVER_HANDSHAKE_TRAFFIC_SECRET"; S = hex2bytes(val); end
    end
    return (C, S)
end

function judge_consistency!(j::Judgment, keylog_path::String; hash::String="SHA256")
    C,S = parse_keylog(keylog_path)
    if C === nothing || S === nothing
        fail!(j, "Key-log missing TLS 1.3 handshake secrets")
        return j
    end
    kC = HKDFHelpers.hkdf_expand_label(C, "key", UInt8[], 16)  # sample derivation
    kS = HKDFHelpers.hkdf_expand_label(S, "key", UInt8[], 16)
    j.artifacts["client_hs_key_sample"] = bytes2hex(kC)
    j.artifacts["server_hs_key_sample"] = bytes2hex(kS)
    pass!(j, "Key-log present and secrets derivable (sample HKDF-Expand-Label)")
    j
end

export judge_consistency!

end
