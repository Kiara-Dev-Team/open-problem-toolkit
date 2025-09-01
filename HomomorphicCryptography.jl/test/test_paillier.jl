@testitem "Paillier - Key Generation" begin
    using HomomorphicCryptography

    scheme = PaillierScheme()
    params = PaillierParameters(SECURITY_128)

    keypair = keygen(scheme, params)
    @test keypair isa KeyPair
    @test keypair.public_key isa PaillierPublicKey
    @test keypair.private_key isa PaillierPrivateKey
    @test keypair.public_key.key_size >= 2047  # Allow for minor variation in prime generation
end

@testitem "Paillier - Encryption and Decryption" begin
    using HomomorphicCryptography

    scheme = PaillierScheme()
    params = PaillierParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    # Test basic encryption/decryption
    test_values = [0, 1, 42, 1337, 999999]

    for val in test_values
        plaintext = PaillierPlaintext(val)
        ciphertext = encrypt(pk, plaintext)
        decrypted = decrypt(sk, ciphertext)

        @test decrypted.value == val
    end

    # Test convenience functions
    val = 12345
    ciphertext = encrypt(pk, val)
    decrypted_val = decrypt_to_int(sk, ciphertext)
    @test decrypted_val == val
end

@testitem "Paillier - Homomorphic Addition" begin
    using HomomorphicCryptography

    scheme = PaillierScheme()
    params = PaillierParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    # Test homomorphic addition
    m1, m2 = 100, 200
    c1 = encrypt(pk, m1)
    c2 = encrypt(pk, m2)

    c_sum = add_encrypted(c1, c2)
    decrypted_sum = decrypt_to_int(sk, c_sum)

    @test decrypted_sum == m1 + m2

    # Test multiple additions
    m3 = 50
    c3 = encrypt(pk, m3)
    c_total = add_encrypted(add_encrypted(c1, c2), c3)
    decrypted_total = decrypt_to_int(sk, c_total)

    @test decrypted_total == m1 + m2 + m3
end

@testitem "Paillier - Plaintext Addition" begin
    using HomomorphicCryptography

    scheme = PaillierScheme()
    params = PaillierParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    m1, m2 = 100, 200
    c1 = encrypt(pk, m1)
    p2 = PaillierPlaintext(m2)

    c_sum = add_plain(c1, p2)
    decrypted_sum = decrypt_to_int(sk, c_sum)

    @test decrypted_sum == m1 + m2
end

@testitem "Paillier - Scalar Multiplication" begin
    using HomomorphicCryptography

    scheme = PaillierScheme()
    params = PaillierParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    m = 50
    scalar = 3
    c = encrypt(pk, m)

    c_mult = multiply_plain(c, scalar)
    decrypted_mult = decrypt_to_int(sk, c_mult)

    @test decrypted_mult == m * scalar
end

@testitem "Paillier - ISO/IEC 18033-6 Compliance" begin
    using HomomorphicCryptography

    scheme = PaillierScheme()
    params = PaillierParameters(SECURITY_128)

    @test validate_iso18033_6_compliance(scheme, params) == true
end

@testitem "Paillier - Scheme Properties" begin
    using HomomorphicCryptography

    scheme = PaillierScheme()

    @test scheme_name(scheme) == "HomomorphicCryptography.PaillierScheme"
    @test is_fully_homomorphic(scheme) == false
    @test is_somewhat_homomorphic(scheme) == false
    @test supports_addition(scheme) == true
    @test supports_multiplication(scheme) == false
end
