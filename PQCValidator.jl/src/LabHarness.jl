module LabHarness

using ..PQCValidator: Judgment, pass!, fail!, finalize!
using ..HKDFHelpers
using ..OQS

const PK=OQS.MLKEM768_PK; const SK=OQS.MLKEM768_SK; const CT=OQS.MLKEM768_CT; const SS=OQS.MLKEM768_SS

# Simplified X25519 implementation (for demonstration purposes only)
# Note: This is NOT cryptographically secure and should not be used in production
x25519_keypair() = begin
    # Generate 32-byte random private key and simulate public key
    sk = rand(UInt8, 32)
    # For demo purposes, use a simple transformation (NOT cryptographically valid)
    pk = [sk[i] ⊻ UInt8(0x42) for i in 1:32]  # XOR with constant
    return (pk, sk)
end

x25519_shared(pk_peer::Vector{UInt8}, sk_self::Vector{UInt8}) = begin
    # Simplified key exchange (NOT cryptographically secure)
    # In real X25519, this would be scalar multiplication on curve25519
    shared = similar(pk_peer)
    for i in 1:32
        shared[i] = pk_peer[i] ⊻ sk_self[i]  # Simple XOR (demo only)
    end
    return shared
end

function judge_lab(; combiner="concat+kdf", hash="SHA256")
    j = Judgment(); j.kem_param = 768; j.combiner = combiner

    # ECDHE
    pk_cli, sk_cli = x25519_keypair()
    pk_srv, sk_srv = x25519_keypair()
    k_ec_c = x25519_shared(pk_srv, sk_cli)
    k_ec_s = x25519_shared(pk_cli, sk_srv)
    (k_ec_c == k_ec_s && length(k_ec_c) == 32) ? pass!(j,"ECDHE share consistent") : fail!(j,"ECDHE mismatch")

    # ML-KEM
    kem = OQS.OQS_KEM_new_ml_kem_768()
    pk = Vector{UInt8}(undef, PK); sk = Vector{UInt8}(undef, SK)
    OQS.OQS_KEM_keypair(kem, pk, sk)
    ct = Vector{UInt8}(undef, CT); ssS = Vector{UInt8}(undef, SS); ssC = Vector{UInt8}(undef, SS)
    OQS.OQS_KEM_encaps(kem, ct, ssS, pk)
    OQS.OQS_KEM_decaps(kem, ssC, ct, sk)
    OQS.OQS_KEM_free(kem)

    (length(pk)==PK && length(ct)==CT && length(ssC)==SS) ? pass!(j,"FIPS-203 ML-KEM-768 sizes OK") : fail!(j,"FIPS size mismatch")
    (ssC == ssS) ? pass!(j,"Encap/decap shared secrets agree") : fail!(j,"Encap/decap mismatch")

    # ETSI combiner (concat then HKDF-Extract with zero salt)
    ikm = vcat(k_ec_c, ssC)
    s0  = HKDFHelpers.hkdf_extract(fill(UInt8(0), 32), ikm)
    k_app = HKDFHelpers.hkdf_expand_label(s0, "key", UInt8[], 16)
    j.artifacts["witness"] = Dict("k_ec_len"=>length(k_ec_c), "k_kem_len"=>length(ssC),
                                  "s0_len"=>length(s0), "k_app_sample"=>bytes2hex(k_app))
    # independence sanity
    s0_zero_ec  = HKDFHelpers.hkdf_extract(fill(UInt8(0), 32), vcat(fill(UInt8(0), length(k_ec_c)), ssC))
    s0_zero_kem = HKDFHelpers.hkdf_extract(fill(UInt8(0), 32), vcat(k_ec_c, fill(UInt8(0), length(ssC))))
    (s0 != s0_zero_ec && s0 != s0_zero_kem) ? pass!(j,"Hybrid non-degenerate") : fail!(j,"Hybrid degeneracy")

    finalize!(j)
end

export judge_lab

end
