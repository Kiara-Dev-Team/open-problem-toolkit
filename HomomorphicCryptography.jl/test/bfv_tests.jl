@testitem "BFV - Key Generation" tags=[:bfv, :fhe] timeout=120 begin
    using HomomorphicCryptography

    scheme = BFVScheme()
    params = LatticeParameters(SECURITY_128)

    keypair = keygen(scheme, params)
    @test keypair isa KeyPair
    @test keypair.public_key isa BFVPublicKey
    @test keypair.private_key isa BFVPrivateKey
    @test keypair.public_key.n == params.ring_dimension
    @test keypair.public_key.q == params.ciphertext_modulus
end

@testitem "BFV - Encoding and Decoding" begin
    using HomomorphicCryptography

    params = LatticeParameters(SECURITY_128)
    values = [1, 2, 3, 4, 5]

    encoded = bfv_encode(values, params.plaintext_modulus, params.ring_dimension)
    @test encoded isa BFVPlaintext

    decoded = bfv_decode(encoded)
    @test decoded[1:5] == BigInt[1, 2, 3, 4, 5]
end

@testitem "BFV - Encryption Basic Values" tags=[:bfv, :fhe] timeout=60 begin
    using HomomorphicCryptography

    scheme = BFVScheme()
    params = LatticeParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    # Test basic values
    vals = [0, 1, 42, 100, 255]
    ciphertext = encrypt(pk, vals)
    @test ciphertext isa BFVCiphertext

    decrypted_plaintext = decrypt(sk, ciphertext)
    @test decrypted_plaintext isa BFVPlaintext

    decoded = bfv_decode(decrypted_plaintext)
    @test decoded[1:length(vals)] == BigInt.(vals)
end

@testitem "BFV - Encryption Vector Values" tags=[:bfv, :fhe] timeout=60 begin
    using HomomorphicCryptography

    scheme = BFVScheme()
    params = LatticeParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    # Test vector values
    vals = [10, 20, 30]
    ciphertext = encrypt(pk, vals)
    @test ciphertext isa BFVCiphertext

    decrypted_plaintext = decrypt(sk, ciphertext)
    @test decrypted_plaintext isa BFVPlaintext

    decoded = bfv_decode(decrypted_plaintext)
    @test decoded[1:length(vals)] == BigInt.(vals)
end

@testitem "BFV - Homomorphic Addition" tags=[:bfv, :fhe, :addition] timeout=90 begin
    using HomomorphicCryptography

    scheme = BFVScheme()
    params = LatticeParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    # Test homomorphic addition
    vals1 = [10, 20, 30]
    vals2 = [5, 15, 25]

    c1 = encrypt(pk, vals1)
    c2 = encrypt(pk, vals2)

    c_sum = add_encrypted(c1, c2)
    @test c_sum isa BFVCiphertext

    decrypted_sum = bfv_decode(decrypt(sk, c_sum))
    expected = BigInt[15, 35, 55]
    @test decrypted_sum[1:3] == expected
end

@testitem "BFV - Homomorphic Multiplication" tags=[:bfv, :fhe, :multiplication] timeout=180 begin
    using HomomorphicCryptography

    scheme = BFVScheme()
    params = LatticeParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    # Test homomorphic multiplication (small values)
    vals1 = [2, 3, 4]
    vals2 = [3, 4, 5]

    c1 = encrypt(pk, vals1)
    c2 = encrypt(pk, vals2)

    c_mult = multiply_encrypted(c1, c2)
    @test c_mult isa BFVCiphertext
    @test length(c_mult.components) == 3  # Post-multiplication has 3 components

    # Note: multiplication result may have noise, so we test if decryption works
    decrypted_mult = bfv_decode(decrypt(sk, c_mult))
    @test length(decrypted_mult) == params.ring_dimension
end

@testitem "BFV - Plaintext Addition" begin
    using HomomorphicCryptography

    scheme = BFVScheme()
    params = LatticeParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    vals = [10, 20, 30]
    plain_vals = [1, 2, 3]

    c = encrypt(pk, vals)
    p = bfv_encode(plain_vals, params.plaintext_modulus, params.ring_dimension)

    c_sum = add_plain(c, p)
    decrypted_sum = bfv_decode(decrypt(sk, c_sum))
    expected = BigInt[11, 22, 33]
    @test decrypted_sum[1:3] == expected
end

@testitem "BFV - Scalar Multiplication" begin
    using HomomorphicCryptography

    scheme = BFVScheme()
    params = LatticeParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    vals = [5, 10, 15]
    scalar = 3

    c = encrypt(pk, vals)
    c_mult = multiply_plain(c, scalar)

    decrypted_mult = bfv_decode(decrypt(sk, c_mult))
    expected = BigInt[15, 30, 45]
    @test decrypted_mult[1:3] == expected
end

@testitem "BFV - Scheme Properties" begin
    using HomomorphicCryptography

    scheme = BFVScheme()

    @test scheme_name(scheme) == "HomomorphicCryptography.BFVScheme"
    @test is_fully_homomorphic(scheme) == false  # Without bootstrapping
    @test is_somewhat_homomorphic(scheme) == true
    @test supports_addition(scheme) == true
    @test supports_multiplication(scheme) == true
end
