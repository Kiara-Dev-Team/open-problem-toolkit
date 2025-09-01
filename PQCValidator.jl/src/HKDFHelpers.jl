module HKDFHelpers
using SHA

# hmac helpers (SHA-256 default)
hmac_sha256(salt::Vector{UInt8}, data::Vector{UInt8}) = SHA.hmac_sha256(salt, data)

function hkdf_extract(salt::Vector{UInt8}, ikm::Vector{UInt8})
    hmac_sha256(salt, ikm)
end

function hkdf_expand(prk::Vector{UInt8}, info::Vector{UInt8}, L::Int)
    out = UInt8[]
    T = UInt8[]
    i = UInt8(1)
    while length(out) < L
        block = hmac_sha256(prk, vcat(T, info, [i]))
        append!(out, block)
        T = block
        i = UInt8(i + 1)
    end
    resize!(out, L)
    out
end

# TLS 1.3 HKDF-Expand-Label (RFC 8446)
function hkdf_expand_label(prk::Vector{UInt8}, label::AbstractString,
                           context::Vector{UInt8}, L::Int)
    full = "tls13 " * label
    L_bytes = [UInt8(div(L,256)), UInt8(mod(L,256))]
    lab = Vector{UInt8}(codeunits(full))
    ctxlen = UInt8(length(context))
    lablen = UInt8(length(lab))
    info = vcat(L_bytes, [lablen], lab, [ctxlen], context)
    hkdf_expand(prk, info, L)
end

export hkdf_extract, hkdf_expand_label

end
