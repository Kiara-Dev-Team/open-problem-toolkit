# Lattice polynomial utilities for rings Z_q[X]/(X^n + 1)

using Random

"""
    PolyZqN

Polynomial in the negacyclic ring Z_q[X]/(X^n + 1).
Coefficients are stored in canonical form in [0, q-1].
"""
struct PolyZqN
    coeffs::Vector{BigInt}
    q::BigInt
    n::Int
end

"""
    PolyZqN(q::Integer, n::Integer; coeffs=zeros(BigInt, n)) -> PolyZqN

Construct a polynomial with given modulus `q` and ring dimension `n`.
"""
function PolyZqN(q::Integer, n::Integer; coeffs::Vector{<:Integer} = zeros(BigInt, n))
    qc = BigInt(q)
    nn = Int(n)
    @assert length(coeffs) == nn "coeff length must equal n"
    # Normalize into [0, q-1]
    c = Vector{BigInt}(undef, nn)
    for i = 1:nn
        c[i] = mod(BigInt(coeffs[i]), qc)
    end
    return PolyZqN(c, qc, nn)
end

"""
    zero_poly(q::Integer, n::Integer) -> PolyZqN
"""
zero_poly(q::Integer, n::Integer) = PolyZqN(q, n; coeffs = zeros(BigInt, n))

"""
    one_poly(q::Integer, n::Integer) -> PolyZqN
"""
function one_poly(q::Integer, n::Integer)
    c = zeros(BigInt, Int(n))
    c[1] = 1
    return PolyZqN(q, n; coeffs = c)
end

"""
    poly_add(a::PolyZqN, b::PolyZqN) -> PolyZqN
"""
function poly_add(a::PolyZqN, b::PolyZqN)
    @assert a.n == b.n && a.q == b.q "ring mismatch"
    c = Vector{BigInt}(undef, a.n)
    for i = 1:a.n
        c[i] = mod(a.coeffs[i] + b.coeffs[i], a.q)
    end
    return PolyZqN(c, a.q, a.n)
end

"""
    poly_sub(a::PolyZqN, b::PolyZqN) -> PolyZqN
"""
function poly_sub(a::PolyZqN, b::PolyZqN)
    @assert a.n == b.n && a.q == b.q "ring mismatch"
    c = Vector{BigInt}(undef, a.n)
    for i = 1:a.n
        c[i] = mod(a.coeffs[i] - b.coeffs[i], a.q)
    end
    return PolyZqN(c, a.q, a.n)
end

"""
    scalar_mul(a::PolyZqN, k::Integer) -> PolyZqN
"""
function scalar_mul(a::PolyZqN, k::Integer)
    kk = BigInt(k)
    c = Vector{BigInt}(undef, a.n)
    for i = 1:a.n
        c[i] = mod(a.coeffs[i] * kk, a.q)
    end
    return PolyZqN(c, a.q, a.n)
end

"""
    poly_mul(a::PolyZqN, b::PolyZqN) -> PolyZqN

Naive negacyclic convolution modulo X^n + 1 (no NTT acceleration).
"""
function poly_mul(a::PolyZqN, b::PolyZqN)
    @assert a.n == b.n && a.q == b.q "ring mismatch"
    n = a.n
    q = a.q
    # Negacyclic convolution: (X^n ≡ -1)
    c = zeros(BigInt, n)
    @inbounds for i = 0:(n-1)
        ai = a.coeffs[i+1]
        for j = 0:(n-1)
            s = i + j
            if s < n
                c[s+1] = mod(c[s+1] + ai * b.coeffs[j+1], q)
            else
                # wrap with sign flip
                idx = s - n
                c[idx+1] = mod(c[idx+1] - ai * b.coeffs[j+1], q)
            end
        end
    end
    return PolyZqN(c, q, n)
end

"""
    poly_mul_ntt(a::PolyZqN, b::PolyZqN) -> PolyZqN

Attempt to multiply using NTT-based negacyclic convolution when parameters allow.
Falls back to schoolbook negacyclic multiplication otherwise.
"""
function poly_mul_ntt(a::PolyZqN, b::PolyZqN)
    @assert a.n == b.n && a.q == b.q "ring mismatch"
    n = a.n
    q = a.q
    # Check for 2n-th primitive root availability
    ζ = try_find_primitive_root_2n(q, n)
    if ζ === nothing || !is_ntt_compatible(q, n)
        return poly_mul(a, b)
    end
    # Perform negacyclic convolution via NTT
    cvec = negacyclic_convolution(a.coeffs, b.coeffs, q, ζ)
    return PolyZqN(cvec, q, n)
end

"""
    centered_mod(x::Integer, q::Integer) -> BigInt

Map x mod q into centered interval (−q/2, q/2].
"""
function centered_mod(x::Integer, q::Integer)
    qq = BigInt(q)
    y = mod(BigInt(x), qq)
    if y > qq ÷ 2
        y -= qq
    end
    return y
end

"""
    random_uniform_poly(n::Integer, q::Integer; rng=Random.default_rng()) -> PolyZqN
"""
function random_uniform_poly(
    n::Integer,
    q::Integer;
    rng::AbstractRNG = Random.default_rng(),
)
    coeffs = [rand(rng, BigInt(0):BigInt(q-1)) for _ = 1:Int(n)]
    return PolyZqN(q, n; coeffs)
end

"""
    from_coeffs_mod_q(coeffs::Vector{<:Integer}, q::Integer) -> PolyZqN
"""
from_coeffs_mod_q(coeffs::Vector{<:Integer}, q::Integer) =
    PolyZqN(q, length(coeffs); coeffs)

export PolyZqN,
    zero_poly,
    one_poly,
    poly_add,
    poly_sub,
    poly_mul,
    poly_mul_ntt,
    scalar_mul,
    centered_mod,
    random_uniform_poly,
    from_coeffs_mod_q

"""
    to_centered_coeffs(p::PolyZqN) -> Vector{BigInt}

Return coefficients mapped to centered interval (−q/2, q/2].
"""
function to_centered_coeffs(p::PolyZqN)
    return [centered_mod(c, p.q) for c in p.coeffs]
end

"""
    linf_norm(p::PolyZqN; centered::Bool = true) -> BigInt

Compute L∞ norm of polynomial coefficients (optionally centered).
"""
function linf_norm(p::PolyZqN; centered::Bool = true)
    coeffs = centered ? to_centered_coeffs(p) : p.coeffs
    maxv = BigInt(0)
    for c in coeffs
        ac = c < 0 ? -c : c
        if ac > maxv
            maxv = ac
        end
    end
    return maxv
end

"""
    l2_norm(p::PolyZqN; centered::Bool = true) -> Float64

Compute L2 norm of polynomial coefficients (optionally centered).
"""
function l2_norm(p::PolyZqN; centered::Bool = true)
    coeffs = centered ? to_centered_coeffs(p) : p.coeffs
    s = 0.0
    for c in coeffs
        x = float(c)
        s += x * x
    end
    return sqrt(s)
end

"""
    coeff_stats(p::PolyZqN; centered::Bool=true) -> NamedTuple

Return simple statistics of coefficients: (min, max, mean, variance).
"""
function coeff_stats(p::PolyZqN; centered::Bool=true)
    coeffs = centered ? to_centered_coeffs(p) : p.coeffs
    n = length(coeffs)
    if n == 0
        return (min=BigInt(0), max=BigInt(0), mean=0.0, variance=0.0)
    end
    minv = coeffs[1]
    maxv = coeffs[1]
    sumv = big"0"
    for c in coeffs
        if c < minv
            minv = c
        end
        if c > maxv
            maxv = c
        end
        sumv += c
    end
    μ = float(sumv) / n
    s2 = 0.0
    for c in coeffs
        d = float(c) - μ
        s2 += d * d
    end
    variance = n > 1 ? s2 / (n - 1) : 0.0
    return (min=minv, max=maxv, mean=μ, variance=variance)
end

export coeff_stats

export to_centered_coeffs, linf_norm, l2_norm
