# Number Theoretic Transform (NTT) utilities

"""
    is_ntt_compatible(q::Integer, n::Integer) -> Bool

Return true if `q` is likely to support a 2n-th root of unity needed for
NTT in Z_q and 2n | (q-1). This is a heuristic check and may be false negative.
"""
function is_ntt_compatible(q::Integer, n::Integer)
    qq = BigInt(q)
    two_n = BigInt(2) * BigInt(n)
    return mod(qq - 1, two_n) == 0
end

"""
    try_find_primitive_root_2n(q::Integer, n::Integer) -> Union{Nothing, BigInt}

Naively search for a 2n-th primitive root of unity modulo prime q.
Returns `ω` if found, otherwise `nothing`.
"""
function try_find_primitive_root_2n(q::Integer, n::Integer)
    qq = BigInt(q)
    two_n = BigInt(2) * BigInt(n)
    if !is_ntt_compatible(qq, n)
        return nothing
    end
    # naive search (only practical for small q)
    factor = div(qq - 1, two_n)
    for g = 2:(q-2)
        ω = powermod(BigInt(g), factor, qq)
        if powermod(ω, two_n, qq) == 1 && powermod(ω, BigInt(n), qq) == qq - 1
            return ω
        end
    end
    return nothing
end

"""
    ntt!(a::Vector{BigInt}, ω::BigInt, q::BigInt)

In-place iterative Cooley–Tukey NTT for length `length(a)` (power of two).
`ω` must be a principal root of unity of that length. Minimal implementation.
"""
function ntt!(a::Vector{BigInt}, ω::BigInt, q::BigInt)
    n = length(a)
    # bit-reversal permutation
    j = 0
    for i = 1:(n-1)
        bit = n >> 1
        while j & bit != 0
            j &= ~bit
            bit >>= 1
        end
        j |= bit
        if i < j+1
            a[i], a[j+1] = a[j+1], a[i]
        end
    end
    len = 2
    while len <= n
        wlen = powermod(ω, div(n, len), q)
        for i = 1:len:n
            w = BigInt(1)
            for j = 0:(div(len, 2)-1)
                u = a[i+j]
                v = mod(a[i+j+div(len, 2)] * w, q)
                a[i+j] = mod(u + v, q)
                a[i+j+div(len, 2)] = mod(u - v, q)
                w = mod(w * wlen, q)
            end
        end
        len <<= 1
    end
    return a
end

"""
    intt!(a::Vector{BigInt}, ω::BigInt, q::BigInt)

Inverse NTT using inverse root. Assumes `ω` is principal root.
"""
function intt!(a::Vector{BigInt}, ω::BigInt, q::BigInt)
    n = length(a)
    ωinv = invmod(ω, q)
    ntt!(a, ωinv, q)
    n_inv = invmod(BigInt(n), q)
    for i = 1:n
        a[i] = mod(a[i] * n_inv, q)
    end
    return a
end

"""
    invmod(a::Integer, q::Integer) -> BigInt

Modular inverse helper.
"""
function invmod(a::Integer, q::Integer)
    # Extended Euclidean algorithm
    aa = mod(BigInt(a), BigInt(q))
    old_r, r = aa, BigInt(q)
    old_s, s = BigInt(1), BigInt(0)
    while r != 0
        qd = div(old_r, r)
        old_r, r = r, old_r - qd * r
        old_s, s = s, old_s - qd * s
    end
    if old_r != 1
        throw(ArgumentError("no inverse"))
    end
    return mod(old_s, q)
end

export is_ntt_compatible, try_find_primitive_root_2n, ntt!, intt!

# Simple plan/caching for repeated NTTs
struct NTTPlan
    q::BigInt
    n::Int
    root::BigInt
end

const NTT_CACHE = IdDict{Tuple{BigInt,Int},NTTPlan}()

"""
    plan_ntt(q::Integer, n::Integer) -> NTTPlan

Get or create an NTT plan with cached primitive root for (q, n).
"""
function plan_ntt(q::Integer, n::Integer)
    key = (BigInt(q), Int(n))
    if haskey(NTT_CACHE, key)
        return NTT_CACHE[key]
    end
    ω = try_find_primitive_root_2n(q, n)
    ω === nothing && throw(ArgumentError("No primitive root for given (q,n)"))
    plan = NTTPlan(BigInt(q), Int(n), ω)
    NTT_CACHE[key] = plan
    return plan
end

"""
    ntt!(a::Vector{BigInt}, plan::NTTPlan)
"""
ntt!(a::Vector{BigInt}, plan::NTTPlan) = ntt!(a, plan.root, plan.q)

"""
    intt!(a::Vector{BigInt}, plan::NTTPlan)
"""
intt!(a::Vector{BigInt}, plan::NTTPlan) = intt!(a, plan.root, plan.q)

"""
    ntt_batch!(vectors::Vector{Vector{BigInt}}, plan::NTTPlan)
"""
function ntt_batch!(vectors::Vector{Vector{BigInt}}, plan::NTTPlan)
    for v in vectors
        ntt!(v, plan)
    end
    return vectors
end

"""
    intt_batch!(vectors::Vector{Vector{BigInt}}, plan::NTTPlan)
"""
function intt_batch!(vectors::Vector{Vector{BigInt}}, plan::NTTPlan)
    for v in vectors
        intt!(v, plan)
    end
    return vectors
end

export NTTPlan, plan_ntt, NTT_CACHE, ntt_batch!, intt_batch!

"""
    negacyclic_convolution(a::Vector{BigInt}, b::Vector{BigInt}, q::BigInt, ζ::BigInt) -> Vector{BigInt}

Compute negacyclic convolution c = a ⊗ b modulo X^n + 1 over Z_q using NTT.
Requires a primitive 2n-th root ζ modulo q; uses ζ^2 as n-th root.
Length of a and b must be n and power-of-two; returned vector has length n.
"""
function negacyclic_convolution(a::Vector{BigInt}, b::Vector{BigInt}, q::BigInt, ζ::BigInt)
    n = length(a)
    @assert length(b) == n "length mismatch"
    @assert (n & (n - 1)) == 0 "n must be power of two"

    # n-th root for NTT
    ωn = powermod(ζ, 2, q)

    # Precompute twists ζ^i and inverse ζ^{-i}
    ζ_pows = Vector{BigInt}(undef, n)
    ζ_inv_pows = Vector{BigInt}(undef, n)
    ζinv = invmod(ζ, q)
    cur = BigInt(1)
    curinv = BigInt(1)
    for i in 1:n
        ζ_pows[i] = cur
        ζ_inv_pows[i] = curinv
        cur = mod(cur * ζ, q)
        curinv = mod(curinv * ζinv, q)
    end

    # Twist inputs
    A = [mod(a[i] * ζ_pows[i], q) for i in 1:n]
    B = [mod(b[i] * ζ_pows[i], q) for i in 1:n]

    # NTT on A and B with ωn
    ntt!(A, ωn, q)
    ntt!(B, ωn, q)

    # Pointwise multiply
    C = Vector{BigInt}(undef, n)
    for i in 1:n
        C[i] = mod(A[i] * B[i], q)
    end

    # Inverse NTT
    intt!(C, ωn, q)

    # Untwist: multiply by ζ^{-i}
    for i in 1:n
        C[i] = mod(C[i] * ζ_inv_pows[i], q)
    end

    return C
end

export negacyclic_convolution
