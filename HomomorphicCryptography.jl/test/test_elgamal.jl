@testitem "ElGamal - Key Generation" begin
    using HomomorphicCryptography

    scheme = ElGamalScheme()
    params = ElGamalParameters(SECURITY_128)

    keypair = keygen(scheme, params)
    @test keypair isa KeyPair
    @test keypair.public_key isa ElGamalPublicKey
    @test keypair.private_key isa ElGamalPrivateKey
    @test keypair.public_key.key_size >= 1024  # ElGamal uses safe primes, actual size varies
end

@testitem "ElGamal - Encryption and Decryption" begin
    using HomomorphicCryptography

    scheme = ElGamalScheme()
    params = ElGamalParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    # Test basic encryption/decryption (small values for ElGamal)
    test_values = [0, 1, 5, 10, 25]

    for val in test_values
        plaintext = ElGamalPlaintext(val)
        ciphertext = encrypt(pk, plaintext)
        decrypted = decrypt(sk, ciphertext)

        @test decrypted.value == val
    end
end

@testitem "ElGamal - Homomorphic Addition" begin
    using HomomorphicCryptography

    scheme = ElGamalScheme()
    params = ElGamalParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    # Test homomorphic addition (small values)
    m1, m2 = 3, 7
    c1 = encrypt(pk, m1)
    c2 = encrypt(pk, m2)

    c_sum = add_encrypted(c1, c2)
    decrypted_sum = decrypt_to_int(sk, c_sum)

    @test decrypted_sum == m1 + m2
end

@testitem "ElGamal - ISO/IEC 18033-6 Compliance" begin
    using HomomorphicCryptography

    scheme = ElGamalScheme()
    params = ElGamalParameters(SECURITY_128)

    @test validate_elgamal_iso18033_6(scheme, params) == true
end
