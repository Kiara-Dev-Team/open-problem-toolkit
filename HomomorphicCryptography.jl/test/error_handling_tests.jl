@testitem "Error Handling - Paillier Invalid Inputs" begin
    using HomomorphicCryptography
    
    scheme = PaillierScheme()
    params = PaillierParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    # Test invalid plaintext range
    @test_throws ArgumentError encrypt(pk, PaillierPlaintext(pk.n))  # Too large
    @test_throws ArgumentError encrypt(pk, PaillierPlaintext(-1))    # Negative

    # Test scalar multiplication with negative scalar
    c = encrypt(pk, 10)
    @test_throws ArgumentError multiply_plain(c, -1)
end

@testitem "Error Handling - ElGamal Invalid Inputs" begin
    using HomomorphicCryptography
    
    # Test ElGamal with negative plaintext
    @test_throws ArgumentError ElGamalPlaintext(-1)
end
