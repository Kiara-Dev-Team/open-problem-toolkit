module OQS
# Requires liboqs on loader path (e.g., macOS: brew install liboqs oqsprovider)
const lib = "liboqs"

const kem_t = Ptr{Cvoid}

function OQS_KEM_new_ml_kem_768()
    kem = ccall((:OQS_KEM_new_ml_kem_768, lib), kem_t, ())
    kem != C_NULL || error("OQS_KEM_new_ml_kem_768 failed to create KEM object")
    return kem
end

OQS_KEM_free(kem::kem_t) = ccall((:OQS_KEM_free, lib), Cvoid, (kem_t,), kem)

function OQS_KEM_keypair(kem::kem_t, pk::Vector{UInt8}, sk::Vector{UInt8})
    ret = ccall((:OQS_KEM_keypair, lib), Cint, (kem_t, Ptr{UInt8}, Ptr{UInt8}), kem, pk, sk)
    ret == 0 || error("OQS_KEM_keypair failed with code $ret")
    return ret
end
function OQS_KEM_encaps(kem::kem_t, ct::Vector{UInt8}, ss::Vector{UInt8}, pk::Vector{UInt8})
    ret = ccall((:OQS_KEM_encaps, lib), Cint, (kem_t, Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}), kem, ct, ss, pk)
    ret == 0 || error("OQS_KEM_encaps failed with code $ret")
    return ret
end
function OQS_KEM_decaps(kem::kem_t, ss::Vector{UInt8}, ct::Vector{UInt8}, sk::Vector{UInt8})
    ret = ccall((:OQS_KEM_decaps, lib), Cint, (kem_t, Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}), kem, ss, ct, sk)
    ret == 0 || error("OQS_KEM_decaps failed with code $ret")
    return ret
end

const MLKEM768_PK  = 1184
const MLKEM768_SK  = 2400
const MLKEM768_CT  = 1088
const MLKEM768_SS  = 32

export OQS_KEM_new_ml_kem_768, OQS_KEM_free, OQS_KEM_keypair, OQS_KEM_encaps, OQS_KEM_decaps
export MLKEM768_PK, MLKEM768_SK, MLKEM768_CT, MLKEM768_SS

end
