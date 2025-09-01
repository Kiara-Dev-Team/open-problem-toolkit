# BGV (Brakerski-Gentry-Vaikuntanathan) somewhat homomorphic encryption scheme
# Features modulus switching and level management for noise control

using Random

# Import from parent module (will be available when included)
# Core types
import ..SomewhatHomomorphicScheme, ..PublicKey, ..PrivateKey, ..Plaintext, ..Ciphertext
import ..SecurityParameters, ..KeyPair, ..get_recommended_parameters
import ..LatticeParameters, ..SecurityLevel, ..SECURITY_128

# Polynomial operations
import ..PolyZqN, ..poly_add, ..poly_sub, ..poly_mul, ..scalar_mul
import ..random_uniform_poly, ..from_coeffs_mod_q, ..centered_mod
import ..zero_poly, ..one_poly

# Sampling
import ..gaussian_poly, ..binomial_poly

"""
    BGVScheme <: SomewhatHomomorphicScheme

Brakerski-Gentry-Vaikuntanathan (BGV) somewhat homomorphic encryption scheme.
Features hierarchical modulus switching for efficient noise management.
"""
struct BGVScheme <: SomewhatHomomorphicScheme
    name::String
    BGVScheme() = new("BGV")
end

"""
    BGVParameters

BGV-specific parameters including modulus chain for level management.
"""
struct BGVParameters
    ring_dimension::Int                    # Polynomial ring dimension (power of 2)
    modulus_chain::Vector{BigInt}         # Chain of moduli q_L > q_{L-1} > ... > q_0
    plaintext_modulus::Int                # Plaintext space modulus t
    noise_parameter::Float64              # Gaussian noise standard deviation
    security_level::SecurityLevel        # Target security level
    max_level::Int                       # Maximum multiplication level
end

"""
    BGVPublicKey <: PublicKey
"""
struct BGVPublicKey <: PublicKey
    a::PolyZqN
    b::PolyZqN
    level::Int        # Current modulus level
    params::BGVParameters
end

"""
    BGVPrivateKey <: PrivateKey
"""
struct BGVPrivateKey <: PrivateKey
    s::PolyZqN
    level::Int        # Current modulus level  
    params::BGVParameters
end

"""
    BGVPlaintext <: Plaintext
"""
struct BGVPlaintext <: Plaintext
    poly::PolyZqN    # Polynomial with coefficients mod t
    level::Int       # Associated level (for noise tracking)
end

"""
    BGVCiphertext <: Ciphertext

BGV ciphertext with level information for modulus switching.
"""
struct BGVCiphertext <: Ciphertext
    components::Vector{PolyZqN}    # Polynomial components mod q_level
    level::Int                     # Current modulus level
    params::BGVParameters
end

"""
    generate_modulus_chain(max_level::Int, base_modulus_bits::Int, 
                          level_step_bits::Int = 60) -> Vector{BigInt}

Generate a chain of moduli for BGV scheme. Each level adds ~level_step_bits bits.
"""
function generate_modulus_chain(max_level::Int, base_modulus_bits::Int, level_step_bits::Int = 60)
    moduli = BigInt[]
    
    # Start with largest modulus (top level)
    current_bits = base_modulus_bits + max_level * level_step_bits
    
    for level in max_level:-1:0
        # Generate a prime with required bit size
        target_bits = base_modulus_bits + level * level_step_bits
        
        # Simple prime generation (for prototype - should use more sophisticated method)
        lower_bound = BigInt(2)^(target_bits - 1)
        upper_bound = BigInt(2)^target_bits - 1
        
        # Find prime in range
        candidate = lower_bound + rand(BigInt(1):BigInt(upper_bound - lower_bound))
        while !isprime(candidate)
            candidate += 1
            if candidate > upper_bound
                candidate = lower_bound
            end
        end
        
        push!(moduli, candidate)
    end
    
    # Reverse to have q_0 < q_1 < ... < q_L
    return reverse(moduli)
end

"""
    BGVParameters(security_level::SecurityLevel = SECURITY_128, max_level::Int = 3) -> BGVParameters

Generate recommended BGV parameters for given security level and maximum multiplication depth.
"""
function BGVParameters(security_level::SecurityLevel = SECURITY_128, max_level::Int = 3)
    # Standard parameters based on security level
    if security_level == SECURITY_128
        n = 4096
        base_bits = 60
        level_step = 60
        t = 65537  # 2^16 + 1 (prime)
        σ = 3.2
    else
        # For higher security, increase parameters
        n = 8192
        base_bits = 80
        level_step = 80
        t = 65537
        σ = 3.2
    end
    
    modulus_chain = generate_modulus_chain(max_level, base_bits, level_step)
    
    return BGVParameters(n, modulus_chain, t, σ, security_level, max_level)
end

"""
    get_recommended_parameters(::Type{BGVScheme}, level::SecurityLevel) -> BGVParameters
"""
function get_recommended_parameters(::Type{BGVScheme}, level::SecurityLevel = SECURITY_128)
    return BGVParameters(level, 3)  # Default to 3 multiplication levels
end

"""
    keygen(::BGVScheme, params::BGVParameters) -> KeyPair{BGVPublicKey, BGVPrivateKey}

Generate BGV key pair at the highest level.
"""
function keygen(
    ::BGVScheme,
    params::BGVParameters;
    rng::AbstractRNG = Random.default_rng()
)
    n = params.ring_dimension
    q_top = params.modulus_chain[end]  # Highest level modulus
    top_level = params.max_level
    σ = params.noise_parameter
    
    # Secret key: small polynomial
    s = binomial_poly(n, q_top, 2; rng = rng)  # Use CBD_2 for security
    
    # Public key generation
    a = random_uniform_poly(n, q_top; rng = rng)
    e = gaussian_poly(n, q_top; sigma = σ, rng = rng)
    
    # b = -a*s + e (mod q)
    as = poly_mul(a, s)
    neg_as = scalar_mul(as, -1)
    b = poly_add(neg_as, e)
    
    pk = BGVPublicKey(a, b, top_level, params)
    sk = BGVPrivateKey(s, top_level, params)
    
    return KeyPair(pk, sk)
end

"""
    bgv_encode(values::Vector{<:Integer}, t::Int, n::Int, level::Int = 0) -> BGVPlaintext

Encode integer vector into BGV plaintext.
"""
function bgv_encode(values::Vector{<:Integer}, t::Int, n::Int, level::Int = 0)
    coeffs = zeros(BigInt, n)
    for i in 1:min(n, length(values))
        coeffs[i] = mod(BigInt(values[i]), BigInt(t))
    end
    
    return BGVPlaintext(PolyZqN(t, n; coeffs = coeffs), level)
end

"""
    bgv_decode(pt::BGVPlaintext) -> Vector{BigInt}

Decode BGV plaintext to integer vector.
"""
bgv_decode(pt::BGVPlaintext) = copy(pt.poly.coeffs)

"""
    encrypt(pk::BGVPublicKey, pt::BGVPlaintext) -> BGVCiphertext

Encrypt plaintext using BGV scheme at the public key's current level.
"""
function encrypt(
    pk::BGVPublicKey,
    pt::BGVPlaintext;
    rng::AbstractRNG = Random.default_rng()
)
    n = pk.params.ring_dimension
    q = pk.params.modulus_chain[pk.level + 1]  # Convert 0-based to 1-based indexing
    t = pk.params.plaintext_modulus
    σ = pk.params.noise_parameter
    
    # Scale plaintext from Z_t to Z_q
    scaling_factor = div(q, BigInt(t))
    scaled_coeffs = [mod(scaling_factor * c, q) for c in pt.poly.coeffs]
    m_poly = PolyZqN(q, n; coeffs = scaled_coeffs)
    
    # Fresh randomness
    u = binomial_poly(n, q, 2; rng = rng)
    e1 = gaussian_poly(n, q; sigma = σ, rng = rng)
    e2 = gaussian_poly(n, q; sigma = σ, rng = rng)
    
    # BGV encryption: c = (c0, c1) where
    # c0 = b*u + e1 + m
    # c1 = a*u + e2
    bu = poly_mul(pk.b, u)
    c0 = poly_add(poly_add(bu, e1), m_poly)
    
    au = poly_mul(pk.a, u)
    c1 = poly_add(au, e2)
    
    return BGVCiphertext([c0, c1], pk.level, pk.params)
end

"""
    decrypt(sk::BGVPrivateKey, ct::BGVCiphertext) -> BGVPlaintext

Decrypt BGV ciphertext.
"""
function decrypt(sk::BGVPrivateKey, ct::BGVCiphertext)
    @assert ct.level == sk.level "Ciphertext and secret key must be at same level"
    @assert length(ct.components) >= 2 "Ciphertext must have at least 2 components"
    
    c0, c1 = ct.components[1], ct.components[2]
    q = ct.params.modulus_chain[ct.level + 1]
    t = ct.params.plaintext_modulus
    n = ct.params.ring_dimension
    
    # Compute m' = c0 + c1*s (mod q)
    c1s = poly_mul(c1, sk.s)
    mp = poly_add(c0, c1s)
    
    # Scale down to Z_t with rounding
    scaling_factor = div(q, BigInt(t))
    coeffs_t = Vector{BigInt}(undef, n)
    
    for i in 1:n
        # Center and scale
        centered_coeff = centered_mod(mp.coeffs[i], q)
        scaled = div(centered_coeff + div(scaling_factor, 2), scaling_factor)  # Round to nearest
        coeffs_t[i] = mod(scaled, BigInt(t))
    end
    
    pt_poly = PolyZqN(t, n; coeffs = coeffs_t)
    return BGVPlaintext(pt_poly, ct.level)
end

"""
    add_encrypted(c1::BGVCiphertext, c2::BGVCiphertext) -> BGVCiphertext

Add two BGV ciphertexts. They must be at the same level.
"""
function add_encrypted(c1::BGVCiphertext, c2::BGVCiphertext)
    @assert c1.level == c2.level "Ciphertexts must be at same level for addition"
    @assert c1.params.ring_dimension == c2.params.ring_dimension
    
    # Component-wise addition
    max_components = max(length(c1.components), length(c2.components))
    result_components = PolyZqN[]
    
    q = c1.params.modulus_chain[c1.level + 1]
    n = c1.params.ring_dimension
    
    for i in 1:max_components
        comp1 = i <= length(c1.components) ? c1.components[i] : zero_poly(q, n)
        comp2 = i <= length(c2.components) ? c2.components[i] : zero_poly(q, n)
        push!(result_components, poly_add(comp1, comp2))
    end
    
    return BGVCiphertext(result_components, c1.level, c1.params)
end

"""
    add_plain(ct::BGVCiphertext, pt::BGVPlaintext) -> BGVCiphertext

Add a plaintext to a BGV ciphertext.
"""
function add_plain(ct::BGVCiphertext, pt::BGVPlaintext)
    q = ct.params.modulus_chain[ct.level + 1]
    t = ct.params.plaintext_modulus
    n = ct.params.ring_dimension
    
    # Scale plaintext to current level
    scaling_factor = div(q, BigInt(t))
    scaled_coeffs = [mod(scaling_factor * c, q) for c in pt.poly.coeffs]
    scaled_pt = PolyZqN(q, n; coeffs = scaled_coeffs)
    
    # Add to c0 component
    result_components = copy(ct.components)
    result_components[1] = poly_add(result_components[1], scaled_pt)
    
    return BGVCiphertext(result_components, ct.level, ct.params)
end

"""
    multiply_encrypted(c1::BGVCiphertext, c2::BGVCiphertext) -> BGVCiphertext

Multiply two BGV ciphertexts. Result has 3 components and increased noise.
The result should be modulus-switched to a lower level to manage noise.
"""
function multiply_encrypted(c1::BGVCiphertext, c2::BGVCiphertext)
    @assert c1.level == c2.level "Ciphertexts must be at same level for multiplication"
    @assert length(c1.components) == 2 && length(c2.components) == 2 "Only fresh ciphertexts supported"
    
    a0, a1 = c1.components
    b0, b1 = c2.components
    
    # BGV multiplication: result = (d0, d1, d2) where
    # d0 = a0*b0, d1 = a0*b1 + a1*b0, d2 = a1*b1
    d0 = poly_mul(a0, b0)
    d1 = poly_add(poly_mul(a0, b1), poly_mul(a1, b0))
    d2 = poly_mul(a1, b1)
    
    return BGVCiphertext([d0, d1, d2], c1.level, c1.params)
end

"""
    multiply_plain(ct::BGVCiphertext, scalar::Integer) -> BGVCiphertext

Multiply BGV ciphertext by a scalar.
"""
function multiply_plain(ct::BGVCiphertext, scalar::Integer)
    result_components = [scalar_mul(comp, scalar) for comp in ct.components]
    return BGVCiphertext(result_components, ct.level, ct.params)
end

"""
    modulus_switch(ct::BGVCiphertext, target_level::Int) -> BGVCiphertext

Switch BGV ciphertext to a lower level (smaller modulus) to reduce noise growth.
This is the key innovation of BGV - trading modulus size for noise reduction.
"""
function modulus_switch(ct::BGVCiphertext, target_level::Int)
    @assert target_level < ct.level "Can only switch to lower level (smaller modulus)"
    @assert target_level >= 0 "Target level must be non-negative"
    
    current_q = ct.params.modulus_chain[ct.level + 1]
    target_q = ct.params.modulus_chain[target_level + 1]
    n = ct.params.ring_dimension
    
    # Note: scaling_factor would be < 1, so we use direct scaling
    
    # Switch each component to new modulus with scaling
    switched_components = PolyZqN[]
    
    for comp in ct.components
        switched_coeffs = Vector{BigInt}(undef, n)
        
        for i in 1:n
            # Scale coefficient: round(target_q / current_q * coeff)
            # Use centered representation for better rounding
            centered_coeff = centered_mod(comp.coeffs[i], current_q)
            
            # Scale and round to target modulus
            scaled = div(centered_coeff * target_q + div(current_q, 2), current_q)
            switched_coeffs[i] = mod(scaled, target_q)
        end
        
        push!(switched_components, PolyZqN(target_q, n; coeffs = switched_coeffs))
    end
    
    return BGVCiphertext(switched_components, target_level, ct.params)
end

"""
    relinearize_bgv(ct::BGVCiphertext, eval_key::Vector{Tuple{PolyZqN, PolyZqN}}) -> BGVCiphertext

Relinearize 3-component BGV ciphertext back to 2 components using evaluation key.
This is a simplified version - full BGV relinearization needs level-aware eval keys.
"""
function relinearize_bgv(ct::BGVCiphertext, eval_key::Vector{Tuple{PolyZqN, PolyZqN}})
    @assert length(ct.components) == 3 "Only 3-component ciphertexts need relinearization"
    
    c0, c1, c2 = ct.components
    
    # Simple relinearization (should be improved with proper key switching)
    if !isempty(eval_key)
        # Use first eval key component for simplification
        rlk_a, rlk_b = eval_key[1]
        
        # Key switching: (c0, c1, c2) -> (c0 + c2*rlk_a, c1 + c2*rlk_b)
        c2_rlk_a = poly_mul(c2, rlk_a)
        c2_rlk_b = poly_mul(c2, rlk_b)
        
        new_c0 = poly_add(c0, c2_rlk_a)
        new_c1 = poly_add(c1, c2_rlk_b)
        
        return BGVCiphertext([new_c0, new_c1], ct.level, ct.params)
    else
        # Fallback: just drop c2 (not secure, for testing only)
        @warn "No evaluation key provided - using insecure fallback"
        return BGVCiphertext([c0, c1], ct.level, ct.params)
    end
end

"""
    bgv_noise_budget(sk::BGVPrivateKey, ct::BGVCiphertext, pt::BGVPlaintext) -> Float64

Estimate remaining noise budget in bits for BGV ciphertext.
"""
function bgv_noise_budget(sk::BGVPrivateKey, ct::BGVCiphertext, pt::BGVPlaintext)
    # Decrypt and compute noise
    c0, c1 = ct.components[1], ct.components[2]
    mp = poly_add(c0, poly_mul(c1, sk.s))
    
    # Expected message
    q = ct.params.modulus_chain[ct.level + 1]
    t = ct.params.plaintext_modulus
    scaling_factor = div(q, BigInt(t))
    expected_coeffs = [mod(scaling_factor * c, q) for c in pt.poly.coeffs]
    
    # Compute noise magnitude
    max_noise = BigInt(0)
    for i in 1:length(mp.coeffs)
        noise_coeff = abs(centered_mod(mp.coeffs[i] - expected_coeffs[i], q))
        max_noise = max(max_noise, noise_coeff)
    end
    
    # Remaining budget in bits
    max_allowed_noise = div(scaling_factor, 2)
    if max_noise > 0
        return log2(Float64(max_allowed_noise) / Float64(max_noise))
    else
        return Float64(bitlength(max_allowed_noise))
    end
end

"""
    suggest_modulus_switch(ct::BGVCiphertext, target_noise_bits::Float64 = 20.0) -> Union{Int, Nothing}

Suggest optimal level for modulus switching based on noise budget target.
"""
function suggest_modulus_switch(ct::BGVCiphertext, target_noise_bits::Float64 = 20.0)
    # Estimate current noise level (simplified)
    current_level = ct.level
    
    # Try switching to each lower level and estimate improvement
    best_level = nothing
    
    for target_level in (current_level-1):-1:0
        # Estimate noise reduction from switching
        current_q = ct.params.modulus_chain[current_level + 1]
        target_q = ct.params.modulus_chain[target_level + 1]
        
        # Rough noise reduction estimate
        noise_reduction_bits = log2(Float64(current_q) / Float64(target_q))
        
        if noise_reduction_bits >= target_noise_bits
            best_level = target_level
            break
        end
    end
    
    return best_level
end

export add_encrypted, add_plain, multiply_encrypted, multiply_plain
export modulus_switch, relinearize_bgv, bgv_noise_budget, suggest_modulus_switch
export BGVScheme, BGVParameters, BGVPublicKey, BGVPrivateKey, BGVPlaintext, BGVCiphertext
export generate_modulus_chain, bgv_encode, bgv_decode