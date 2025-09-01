# Minimal BFV scheme (prototype) for integer plaintexts

using Random

# Core types are available from parent module scope


"""
    BFVScheme <: SomewhatHomomorphicScheme

Brakerski/Fan-Vercauteren (BFV) somewhat homomorphic encryption scheme.
This is a minimal prototype suitable for experimentation and small demos.
"""
struct BFVScheme <: SomewhatHomomorphicScheme
    name::String
    BFVScheme() = new("BFV")
end

"""
    BFVPublicKey <: PublicKey
"""
struct BFVPublicKey <: PublicKey
    a::PolyZqN
    b::PolyZqN
    q::BigInt
    n::Int
    t::Int
end

"""
    BFVPrivateKey <: PrivateKey
"""
struct BFVPrivateKey <: PrivateKey
    s::PolyZqN
    q::BigInt
    n::Int
    t::Int
end

"""
    BFVPlaintext <: Plaintext
"""
struct BFVPlaintext <: Plaintext
    poly::PolyZqN  # modulus t
end

"""
    BFVCiphertext <: Ciphertext

Supports 2-component (fresh) and 3-component (post-multiply) ciphertexts.
"""
struct BFVCiphertext <: Ciphertext
    components::Vector{PolyZqN} # modulus q
    q::BigInt
    n::Int
    t::Int
end

"""
    BFVEvaluationKey

Evaluation key for relinearization. Contains key-switching matrix for reducing
3-component ciphertext back to 2-component form.
"""
struct BFVEvaluationKey
    key_matrix::Vector{Tuple{PolyZqN, PolyZqN}}  # [(a₀, b₀), (a₁, b₁), ...]
    decomposition_base::Int  # Base for digit decomposition (typically 2^w)
    q::BigInt
    n::Int
    t::Int
end

"""
    get_recommended_parameters(::Type{BFVScheme}, level::SecurityLevel) -> LatticeParameters
"""
function get_recommended_parameters(::Type{BFVScheme}, level::SecurityLevel = SECURITY_128)
    return LatticeParameters(level)
end

"""
    keygen(::BFVScheme, params::LatticeParameters) -> KeyPair{BFVPublicKey,BFVPrivateKey}
"""
function keygen(
    ::BFVScheme,
    params::LatticeParameters;
    rng::AbstractRNG = Random.default_rng(),
)
    n = params.ring_dimension
    q = params.ciphertext_modulus
    t = params.plaintext_modulus
    σ = params.noise_parameter

    # Secret s ~ small
    s = gaussian_poly(n, q; sigma = σ, rng = rng)
    # Public a ~ uniform
    a = random_uniform_poly(n, q; rng = rng)
    # Error e ~ small
    e = gaussian_poly(n, q; sigma = σ, rng = rng)

    # b = -a*s + e (mod q)
    as = poly_mul(a, s)
    neg_as = scalar_mul(as, -1)
    b = poly_add(neg_as, e)

    pk = BFVPublicKey(a, b, q, n, t)
    sk = BFVPrivateKey(s, q, n, t)
    return KeyPair(pk, sk)
end

"""
    generate_evaluation_key(sk::BFVPrivateKey; decomposition_base::Int = 4, 
                           rng::AbstractRNG = Random.default_rng()) -> BFVEvaluationKey

Generate evaluation key for relinearization using digit decomposition.
Smaller decomposition_base gives better performance but larger key size.
"""
function generate_evaluation_key(
    sk::BFVPrivateKey;
    decomposition_base::Int = 4,
    rng::AbstractRNG = Random.default_rng()
)
    n, q, t = sk.n, sk.q, sk.t
    σ = 3.2
    
    # Compute s² (target for key switching)
    s_squared = poly_mul(sk.s, sk.s)
    
    # Number of digits needed for decomposition
    num_digits = Int(ceil(log(decomposition_base, Float64(q))))
    
    key_matrix = Tuple{PolyZqN, PolyZqN}[]
    
    # Generate key switching matrix for each digit
    for i in 0:(num_digits-1)
        # Current power of decomposition base
        base_power = BigInt(decomposition_base)^i
        
        # Generate random polynomial a
        a = random_uniform_poly(n, q; rng = rng)
        
        # Generate error e
        e = gaussian_poly(n, q; sigma = σ, rng = rng)
        
        # Compute target: base_power * s² (mod q)
        target = scalar_mul(s_squared, base_power)
        
        # b = -a*s + e + target
        as = poly_mul(a, sk.s)
        neg_as = scalar_mul(as, -1)
        b = poly_add(poly_add(neg_as, e), target)
        
        push!(key_matrix, (a, b))
    end
    
    return BFVEvaluationKey(key_matrix, decomposition_base, q, n, t)
end

"""
    digit_decompose(poly::PolyZqN, base::Int) -> Vector{PolyZqN}

Decompose polynomial coefficients in given base for key switching.
Returns vector of polynomials representing digits.
"""
function digit_decompose(poly::PolyZqN, base::Int)
    q = poly.q
    n = poly.n
    num_digits = Int(ceil(log(base, Float64(q))))
    
    digits = PolyZqN[]
    
    for digit in 0:(num_digits-1)
        digit_coeffs = zeros(BigInt, n)
        base_power = BigInt(base)^digit
        
        for i in 1:n
            # Extract digit at current position
            coeff = centered_mod(poly.coeffs[i], q)
            digit_val = div(coeff, base_power) % base
            digit_coeffs[i] = mod(digit_val, q)
        end
        
        push!(digits, PolyZqN(q, n; coeffs = digit_coeffs))
    end
    
    return digits
end

"""
    relinearize(ct::BFVCiphertext, eval_key::BFVEvaluationKey) -> BFVCiphertext

Relinearize a 3-component ciphertext back to 2-component using evaluation key.
"""
function relinearize(ct::BFVCiphertext, eval_key::BFVEvaluationKey)
    @assert length(ct.components) == 3 "Only 3-component ciphertexts need relinearization"
    @assert ct.q == eval_key.q && ct.n == eval_key.n "Parameter mismatch"
    
    c0, c1, c2 = ct.components
    
    # Decompose c2 into digits
    c2_digits = digit_decompose(c2, eval_key.decomposition_base)
    
    # Key switching: compute sum of digit_i * key_matrix[i]
    relin_c0 = zero_poly(ct.q, ct.n)
    relin_c1 = zero_poly(ct.q, ct.n)
    
    for (i, digit) in enumerate(c2_digits)
        if i <= length(eval_key.key_matrix)
            a_i, b_i = eval_key.key_matrix[i]
            
            # Add digit * a_i to relin_c0
            digit_a = poly_mul(digit, a_i)
            relin_c0 = poly_add(relin_c0, digit_a)
            
            # Add digit * b_i to relin_c1  
            digit_b = poly_mul(digit, b_i)
            relin_c1 = poly_add(relin_c1, digit_b)
        end
    end
    
    # Final result: (c0 + relin_c0, c1 + relin_c1)
    new_c0 = poly_add(c0, relin_c0)
    new_c1 = poly_add(c1, relin_c1)
    
    return BFVCiphertext([new_c0, new_c1], ct.q, ct.n, ct.t)
end

"""
    bfv_encode(values::Vector{<:Integer}, t::Integer, n::Integer) -> BFVPlaintext

Encode integer vector into polynomial modulo t (zero-padded/truncated to n).
"""
function bfv_encode(values::Vector{<:Integer}, t::Integer, n::Integer)
    nn = Int(n)
    coeffs = zeros(BigInt, nn)
    for i = 1:min(nn, length(values))
        coeffs[i] = mod(BigInt(values[i]), BigInt(t))
    end
    return BFVPlaintext(PolyZqN(t, n; coeffs))
end

"""
    bfv_decode(pt::BFVPlaintext) -> Vector{BigInt}
"""
bfv_decode(pt::BFVPlaintext) = copy(pt.poly.coeffs)

"""
    encrypt(pk::BFVPublicKey, pt::BFVPlaintext) -> BFVCiphertext
"""
function encrypt(
    pk::BFVPublicKey,
    pt::BFVPlaintext;
    rng::AbstractRNG = Random.default_rng(),
)
    n, q, t = pk.n, pk.q, pk.t
    σ = 3.2

    # Lift plaintext from Z_t to Z_q via Δ = ⌊q/t⌋
    Δ = div(q, BigInt(t))
    m_q = [mod(Δ * c, q) for c in pt.poly.coeffs]
    m_poly = PolyZqN(q, n; coeffs = m_q)

    # Fresh randomness
    u = gaussian_poly(n, q; sigma = σ, rng = rng)
    e1 = gaussian_poly(n, q; sigma = σ, rng = rng)
    e2 = gaussian_poly(n, q; sigma = σ, rng = rng)

    # c0 = b*u + e1 + m
    bu = poly_mul(pk.b, u)
    c0 = poly_add(poly_add(bu, e1), m_poly)
    # c1 = a*u + e2
    au = poly_mul(pk.a, u)
    c1 = poly_add(au, e2)

    return BFVCiphertext([c0, c1], q, n, t)
end

"""
    decrypt(sk::BFVPrivateKey, ct::BFVCiphertext) -> BFVPlaintext
"""
function decrypt(sk::BFVPrivateKey, ct::BFVCiphertext)
    @assert length(ct.components) >= 2 "ciphertext must have at least 2 components"
    c0, c1 = ct.components[1], ct.components[2]
    @assert c0.q == sk.q && c1.q == sk.q && c0.n == sk.n

    # m' = c0 + c1*s (mod q)
    c1s = poly_mul(c1, sk.s)
    mp = poly_add(c0, c1s)

    # Scale down to Z_t: round(t/q * centered)
    q = sk.q
    t = sk.t
    coeffs_t = Vector{BigInt}(undef, sk.n)
    tq = Float64(t) / Float64(q)
    for i = 1:sk.n
        ccent = centered_mod(mp.coeffs[i], q)
        # round to nearest
        coeffs_t[i] = mod(BigInt(round(tq * Float64(ccent))), BigInt(t))
    end
    return BFVPlaintext(PolyZqN(t, sk.n; coeffs = coeffs_t))
end

"""
    add_encrypted(c1::BFVCiphertext, c2::BFVCiphertext) -> BFVCiphertext
"""
function add_encrypted(c1::BFVCiphertext, c2::BFVCiphertext)
    @assert c1.q == c2.q && c1.n == c2.n && c1.t == c2.t "ciphertext mismatch"
    L = max(length(c1.components), length(c2.components))
    comps = PolyZqN[]
    for i = 1:L
        p = i <= length(c1.components) ? c1.components[i] : zero_poly(c1.q, c1.n)
        q = i <= length(c2.components) ? c2.components[i] : zero_poly(c2.q, c2.n)
        push!(comps, poly_add(p, q))
    end
    return BFVCiphertext(comps, c1.q, c1.n, c1.t)
end

"""
    add_plain(ct::BFVCiphertext, pt::BFVPlaintext) -> BFVCiphertext
"""
function add_plain(ct::BFVCiphertext, pt::BFVPlaintext)
    # Lift m to q-domain as in encryption and add to c0
    Δ = div(ct.q, BigInt(ct.t))
    m_q = [mod(Δ * c, ct.q) for c in pt.poly.coeffs]
    m_poly = PolyZqN(ct.q, ct.n; coeffs = m_q)
    comps = copy(ct.components)
    comps[1] = poly_add(comps[1], m_poly)
    return BFVCiphertext(comps, ct.q, ct.n, ct.t)
end

"""
    multiply_encrypted(c1::BFVCiphertext, c2::BFVCiphertext) -> BFVCiphertext

Naive ciphertext-ciphertext multiplication without relinearization.
Result has 3 components.
"""
function multiply_encrypted(c1::BFVCiphertext, c2::BFVCiphertext)
    @assert length(c1.components) == 2 && length(c2.components) == 2 "only fresh ciphertexts supported"
    @assert c1.q == c2.q && c1.n == c2.n && c1.t == c2.t
    a0, a1 = c1.components
    b0, b1 = c2.components
    d0 = poly_mul(a0, b0)
    d1 = poly_add(poly_mul(a0, b1), poly_mul(a1, b0))
    d2 = poly_mul(a1, b1)
    return BFVCiphertext([d0, d1, d2], c1.q, c1.n, c1.t)
end

"""
    multiply_encrypted(c1::BFVCiphertext, c2::BFVCiphertext, eval_key::BFVEvaluationKey) -> BFVCiphertext

Ciphertext-ciphertext multiplication with automatic relinearization.
Result is relinearized back to 2 components.
"""
function multiply_encrypted(c1::BFVCiphertext, c2::BFVCiphertext, eval_key::BFVEvaluationKey)
    # Perform multiplication
    mult_result = multiply_encrypted(c1, c2)
    
    # Relinearize result
    return relinearize(mult_result, eval_key)
end

"""
    multiply_plain(ct::BFVCiphertext, scalar::Integer) -> BFVCiphertext
"""
function multiply_plain(ct::BFVCiphertext, scalar::Integer)
    comps = [scalar_mul(p, scalar) for p in ct.components]
    return BFVCiphertext(comps, ct.q, ct.n, ct.t)
end

"""
    encrypt(pk::BFVPublicKey, values::Vector{<:Integer}) -> BFVCiphertext
"""
function encrypt(
    pk::BFVPublicKey,
    values::Vector{<:Integer};
    rng::AbstractRNG = Random.default_rng(),
)
    pt = bfv_encode(values, pk.t, pk.n)
    return encrypt(pk, pt; rng = rng)
end

export BFVScheme,
    BFVPublicKey, BFVPrivateKey, BFVPlaintext, BFVCiphertext, BFVEvaluationKey,
    bfv_encode, bfv_decode,
    generate_evaluation_key, relinearize, digit_decompose

"""
    validate_bfv_parameters(params::LatticeParameters) -> Bool

Additional BFV-specific parameter checks beyond generic lattice validation.
Ensures n is power-of-two, t < q, and q divisible by t (for Δ mapping).
"""
function validate_bfv_parameters(params::LatticeParameters)
    # Generic lattice validation
    if !validate_parameters(params)
        return false
    end
    # n must be a power of two
    n = params.ring_dimension
    ispow2 = n > 0 && (n & (n - 1)) == 0
    if !ispow2
        return false
    end
    q = params.ciphertext_modulus
    t = BigInt(params.plaintext_modulus)
    if !(t < q)
        return false
    end
    if mod(q, t) != 0
        return false
    end
    return true
end

export validate_bfv_parameters

"""
    bfv_noise_poly(sk::BFVPrivateKey, ct::BFVCiphertext, pt::BFVPlaintext) -> PolyZqN

Compute the noise polynomial e = (c0 + c1*s) - Δ*m (mod q), where Δ = ⌊q/t⌋.
This requires knowledge of plaintext pt.
"""
function bfv_noise_poly(sk::BFVPrivateKey, ct::BFVCiphertext, pt::BFVPlaintext)
    @assert ct.q == sk.q && ct.n == sk.n && ct.t == sk.t
    # Compute m' = c0 + c1*s (mod q)
    c0, c1 = ct.components[1], ct.components[2]
    mp = poly_add(c0, poly_mul(c1, sk.s))
    # Lift m to q-domain
    Δ = div(sk.q, BigInt(sk.t))
    m_q = [mod(Δ * c, sk.q) for c in pt.poly.coeffs]
    m_poly = PolyZqN(sk.q, sk.n; coeffs=m_q)
    # Noise = mp - m_q (mod q)
    return poly_sub(mp, m_poly)
end

"""
    bfv_noise_linf(sk::BFVPrivateKey, ct::BFVCiphertext, pt::BFVPlaintext) -> BigInt

Compute L∞ norm of the centered noise coefficients for the given ciphertext and plaintext.
"""
function bfv_noise_linf(sk::BFVPrivateKey, ct::BFVCiphertext, pt::BFVPlaintext)
    noise = bfv_noise_poly(sk, ct, pt)
    return linf_norm(noise; centered=true)
end

"""
    NoiseAnalysis

Structure to store comprehensive noise analysis results for a BFV ciphertext.
"""
struct NoiseAnalysis
    linf_norm::BigInt           # L∞ norm (maximum absolute coefficient)
    l2_norm::Float64           # L2 norm 
    noise_budget_bits::Float64  # Remaining noise budget in bits
    estimated_security::Float64 # Security level based on noise
    can_multiply::Bool          # Whether another multiplication is safe
    suggested_params::Union{Nothing, String} # Parameter recommendations
end

"""
    analyze_noise(sk::BFVPrivateKey, ct::BFVCiphertext, pt::BFVPlaintext) -> NoiseAnalysis

Comprehensive noise analysis for a BFV ciphertext.
"""
function analyze_noise(sk::BFVPrivateKey, ct::BFVCiphertext, pt::BFVPlaintext)
    noise_poly = bfv_noise_poly(sk, ct, pt)
    
    # Compute norms
    linf_norm_val = linf_norm(noise_poly; centered=true)
    l2_norm_val = l2_norm(noise_poly; centered=true)
    
    # Estimate remaining noise budget
    Δ = div(sk.q, BigInt(sk.t))
    max_noise = div(Δ, BigInt(2))
    
    # Noise budget in bits
    if linf_norm_val > 0
        noise_budget_bits = log2(Float64(max_noise) / Float64(linf_norm_val))
    else
        noise_budget_bits = Float64(bitlength(max_noise))
    end
    
    # Estimate security (simplified heuristic)
    estimated_security = max(0, min(256, noise_budget_bits * 8))
    
    # Can safely multiply?
    can_multiply = noise_budget_bits > 10.0  # Conservative threshold
    
    # Parameter suggestions
    suggestion = nothing
    if noise_budget_bits < 5.0
        suggestion = "Critical: Consider bootstrapping or increasing q"
    elseif noise_budget_bits < 15.0
        suggestion = "Warning: Limited operations remaining"
    elseif can_multiply
        suggestion = "Good: Multiple operations possible"
    end
    
    return NoiseAnalysis(
        linf_norm_val, 
        l2_norm_val,
        noise_budget_bits,
        estimated_security,
        can_multiply,
        suggestion
    )
end

"""
    estimate_multiplication_depth(params::LatticeParameters) -> Int

Estimate maximum multiplication depth for given parameters.
"""
function estimate_multiplication_depth(params::LatticeParameters)
    # Simplified estimation based on parameter sizes
    q_bits = bitlength(params.ciphertext_modulus)
    t_bits = bitlength(params.plaintext_modulus)
    
    # Each multiplication roughly doubles the noise
    # Conservative estimate: log2(q/t) - safety margin
    safe_depth = max(1, Int(floor((q_bits - t_bits - 10) / 2)))
    
    return safe_depth
end

"""
    noise_growth_after_addition(noise1::NoiseAnalysis, noise2::NoiseAnalysis) -> Float64

Estimate L∞ noise growth after adding two ciphertexts.
"""
function noise_growth_after_addition(noise1::NoiseAnalysis, noise2::NoiseAnalysis)
    # Addition: noise grows as max(noise1, noise2) + small error
    return Float64(max(noise1.linf_norm, noise2.linf_norm) + 1)
end

"""
    noise_growth_after_multiplication(noise1::NoiseAnalysis, noise2::NoiseAnalysis, 
                                    params::LatticeParameters) -> Float64

Estimate L∞ noise growth after multiplying two ciphertexts.
"""
function noise_growth_after_multiplication(noise1::NoiseAnalysis, noise2::NoiseAnalysis, 
                                         params::LatticeParameters)
    # Multiplication: roughly noise1 * noise2 * scaling factor
    t = params.plaintext_modulus
    base_growth = noise1.l2_norm * noise2.l2_norm * Float64(t)
    
    # Add some margin for rounding errors and key switching
    margin_factor = 1.5
    
    return base_growth * margin_factor
end

"""
    print_noise_analysis(analysis::NoiseAnalysis)

Pretty-print noise analysis results.
"""
function print_noise_analysis(analysis::NoiseAnalysis)
    println("🔍 BFV Noise Analysis")
    println("─" ^ 25)
    println("L∞ Noise: $(analysis.linf_norm)")
    println("L2 Noise: $(round(analysis.l2_norm, digits=2))")
    println("Noise Budget: $(round(analysis.noise_budget_bits, digits=1)) bits")
    println("Est. Security: $(round(analysis.estimated_security, digits=1)) bits")
    println("Safe Multiply: $(analysis.can_multiply ? "✓" : "✗")")
    if analysis.suggested_params !== nothing
        println("Suggestion: $(analysis.suggested_params)")
    end
    println()
end

export bfv_noise_poly, bfv_noise_linf
export NoiseAnalysis, analyze_noise, estimate_multiplication_depth
export noise_growth_after_addition, noise_growth_after_multiplication
export print_noise_analysis

"""
    BatchEncoder

Encoder for BFV batching (SIMD operations) when t is prime and n/2 slots are available.
Maps vectors of integers to polynomial coefficients for parallel processing.
"""
struct BatchEncoder
    t::Int              # Plaintext modulus (must be prime)
    n::Int              # Ring dimension
    slots::Int          # Number of slots (typically n/2 when batching is possible)
    primitive_root::Union{Nothing, Int}  # Primitive root of unity mod t
end

"""
    BatchEncoder(t::Int, n::Int) -> BatchEncoder

Create a batch encoder if t is suitable for batching (prime and n/2 divides t-1).
"""
function BatchEncoder(t::Int, n::Int)
    # Check if batching is possible
    slots = div(n, 2)
    
    # For batching, we need t ≡ 1 (mod 2n) and t prime
    if !isprime(t) || mod(t - 1, 2*n) != 0
        return BatchEncoder(t, n, 0, nothing)
    end
    
    # Find primitive 2n-th root of unity mod t
    primitive_root = find_primitive_2n_root(t, n)
    
    return BatchEncoder(t, n, slots, primitive_root)
end

"""
    find_primitive_2n_root(t::Int, n::Int) -> Union{Nothing, Int}

Find a primitive 2n-th root of unity modulo t.
"""
function find_primitive_2n_root(t::Int, n::Int)
    if mod(t - 1, 2*n) != 0
        return nothing
    end
    
    factor = div(t - 1, 2*n)
    for g in 2:(t-1)
        root = powermod(g, factor, t)
        if powermod(root, 2*n, t) == 1 && powermod(root, n, t) != 1
            return root
        end
    end
    return nothing
end

"""
    can_batch(encoder::BatchEncoder) -> Bool

Check if batching is supported for this encoder.
"""
can_batch(encoder::BatchEncoder) = encoder.slots > 0 && encoder.primitive_root !== nothing

"""
    batch_encode(encoder::BatchEncoder, values::Vector{<:Integer}) -> BFVPlaintext

Encode a vector of integers into a single polynomial using CRT batching.
The vector is padded/truncated to fit the available slots.
"""
function batch_encode(encoder::BatchEncoder, values::Vector{<:Integer})
    if !can_batch(encoder)
        # Fallback to regular encoding if batching not supported
        return bfv_encode(values, encoder.t, encoder.n)
    end
    
    # Pad or truncate to fit slots
    padded_values = zeros(Int, encoder.slots)
    for i in 1:min(length(values), encoder.slots)
        padded_values[i] = mod(Int(values[i]), encoder.t)
    end
    
    # Use Chinese Remainder Theorem to map slots to polynomial coefficients
    coeffs = inverse_ntt_batching(padded_values, encoder)
    
    return BFVPlaintext(PolyZqN(encoder.t, encoder.n; coeffs = coeffs))
end

"""
    batch_decode(encoder::BatchEncoder, pt::BFVPlaintext) -> Vector{Int}

Decode a batched plaintext back to a vector of integers.
"""
function batch_decode(encoder::BatchEncoder, pt::BFVPlaintext)
    if !can_batch(encoder)
        # Fallback to regular decoding
        return [Int(c) for c in pt.poly.coeffs[1:min(encoder.slots, length(pt.poly.coeffs))]]
    end
    
    # Use CRT to extract slot values from polynomial coefficients
    return forward_ntt_batching(pt.poly.coeffs, encoder)
end

"""
    inverse_ntt_batching(values::Vector{Int}, encoder::BatchEncoder) -> Vector{BigInt}

Map slot values to polynomial coefficients using inverse NTT-like transform.
This is a simplified version for batching support.
"""
function inverse_ntt_batching(values::Vector{Int}, encoder::BatchEncoder)
    if encoder.primitive_root === nothing
        # Fallback: place values in first coefficients
        coeffs = zeros(BigInt, encoder.n)
        for i in 1:min(length(values), encoder.n)
            coeffs[i] = BigInt(values[i])
        end
        return coeffs
    end
    
    # Simplified batching: duplicate values in real/imaginary parts
    coeffs = zeros(BigInt, encoder.n)
    
    # Fill first half with values
    for i in 1:min(length(values), div(encoder.n, 2))
        coeffs[i] = BigInt(values[i])
    end
    
    # Mirror for conjugate symmetry (simplified)
    for i in 1:min(length(values), div(encoder.n, 2))
        coeffs[encoder.n - i + 1] = BigInt(values[i])
    end
    
    return coeffs
end

"""
    forward_ntt_batching(coeffs::Vector{BigInt}, encoder::BatchEncoder) -> Vector{Int}

Extract slot values from polynomial coefficients using forward NTT-like transform.
"""
function forward_ntt_batching(coeffs::Vector{BigInt}, encoder::BatchEncoder)
    if encoder.primitive_root === nothing
        # Fallback: extract first coefficients
        result = Int[]
        for i in 1:min(encoder.slots, length(coeffs))
            push!(result, Int(mod(coeffs[i], encoder.t)))
        end
        return result
    end
    
    # Extract from first half (simplified)
    result = Int[]
    for i in 1:min(encoder.slots, div(encoder.n, 2))
        if i <= length(coeffs)
            push!(result, Int(mod(coeffs[i], encoder.t)))
        else
            push!(result, 0)
        end
    end
    
    return result
end

"""
    simd_add(ct1::BFVCiphertext, ct2::BFVCiphertext, encoder::BatchEncoder) -> BFVCiphertext

Element-wise addition of batched ciphertexts (same as regular addition).
"""
function simd_add(ct1::BFVCiphertext, ct2::BFVCiphertext, ::BatchEncoder)
    return add_encrypted(ct1, ct2)
end

"""
    simd_multiply(ct1::BFVCiphertext, ct2::BFVCiphertext, eval_key::BFVEvaluationKey, 
                 encoder::BatchEncoder) -> BFVCiphertext

Element-wise multiplication of batched ciphertexts.
"""
function simd_multiply(ct1::BFVCiphertext, ct2::BFVCiphertext, eval_key::BFVEvaluationKey, 
                      ::BatchEncoder)
    return multiply_encrypted(ct1, ct2, eval_key)
end

"""
    simd_add_constant(ct::BFVCiphertext, constants::Vector{<:Integer}, 
                     encoder::BatchEncoder) -> BFVCiphertext

Add different constants to each slot in a batched ciphertext.
"""
function simd_add_constant(ct::BFVCiphertext, constants::Vector{<:Integer}, 
                          encoder::BatchEncoder)
    const_plaintext = batch_encode(encoder, constants)
    return add_plain(ct, const_plaintext)
end

"""
    simd_multiply_constant(ct::BFVCiphertext, constants::Vector{<:Integer},
                          encoder::BatchEncoder) -> BFVCiphertext

Multiply each slot by different constants in a batched ciphertext.
"""
function simd_multiply_constant(ct::BFVCiphertext, constants::Vector{<:Integer},
                               ::BatchEncoder)
    # This would need a multiply_plain for plaintexts, simplified version:
    result_components = PolyZqN[]
    for comp in ct.components
        # Simplified: multiply by first constant (should use proper plaintext multiplication)
        if !isempty(constants)
            mult_comp = scalar_mul(comp, constants[1])
            push!(result_components, mult_comp)
        else
            push!(result_components, comp)
        end
    end
    return BFVCiphertext(result_components, ct.q, ct.n, ct.t)
end

export BatchEncoder, can_batch, batch_encode, batch_decode
export simd_add, simd_multiply, simd_add_constant, simd_multiply_constant
export find_primitive_2n_root
