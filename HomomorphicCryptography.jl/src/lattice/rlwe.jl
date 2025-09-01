# RLWE utilities and simple helpers

using Random

"""
    RLWEParams

Parameters for RLWE instances over Z_q[X]/(X^n + 1) with Gaussian noise.
"""
struct RLWEParams
    n::Int
    q::BigInt
    sigma::Float64
end

"""
    RLWEPublicKey
"""
struct RLWEPublicKey
    a::PolyZqN
    b::PolyZqN
end

"""
    RLWESecretKey
"""
struct RLWESecretKey
    s::PolyZqN
end

"""
    sample_rlwe_instance(params::RLWEParams; rng=Random.default_rng()) -> (a, t)

Sample a pair (a, t = a*s + e) with fresh secret s and error e.
This is useful as a plain RLWE problem instance.
"""
function sample_rlwe_instance(params::RLWEParams; rng::AbstractRNG = Random.default_rng())
    n, q, σ = params.n, params.q, params.sigma
    a = random_uniform_poly(n, q; rng=rng)
    s = gaussian_poly(n, q; sigma=σ, rng=rng)
    e = gaussian_poly(n, q; sigma=σ, rng=rng)
    t = poly_add(poly_mul(a, s), e)
    return (a, t)
end

"""
    rlwe_keygen(params::RLWEParams; rng) -> (pk, sk)
"""
function rlwe_keygen(params::RLWEParams; rng::AbstractRNG = Random.default_rng())
    n, q, σ = params.n, params.q, params.sigma
    s = gaussian_poly(n, q; sigma=σ, rng=rng)
    a = random_uniform_poly(n, q; rng=rng)
    e = gaussian_poly(n, q; sigma=σ, rng=rng)
    # b = -a*s + e
    b = poly_add(scalar_mul(poly_mul(a, s), -1), e)
    return RLWEPublicKey(a, b), RLWESecretKey(s)
end

"""
    rlwe_encrypt(pk::RLWEPublicKey, m::PolyZqN; rng) -> (c0, c1)

Encrypt small-norm message polynomial m under RLWE public key.
"""
function rlwe_encrypt(
    pk::RLWEPublicKey,
    m::PolyZqN;
    rng::AbstractRNG = Random.default_rng(),
)
    n, q = pk.a.n, pk.a.q
    σ = 3.2
    u = gaussian_poly(n, q; sigma=σ, rng=rng)
    e1 = gaussian_poly(n, q; sigma=σ, rng=rng)
    e2 = gaussian_poly(n, q; sigma=σ, rng=rng)

    c0 = poly_add(poly_mul(pk.b, u), e1) |> x -> poly_add(x, m)
    c1 = poly_add(poly_mul(pk.a, u), e2)
    return (c0, c1)
end

"""
    rlwe_decrypt(sk::RLWESecretKey, c0::PolyZqN, c1::PolyZqN) -> PolyZqN
"""
function rlwe_decrypt(sk::RLWESecretKey, c0::PolyZqN, c1::PolyZqN)
    return poly_add(c0, poly_mul(c1, sk.s))
end

export RLWEParams, RLWEPublicKey, RLWESecretKey, sample_rlwe_instance,
       rlwe_keygen, rlwe_encrypt, rlwe_decrypt

