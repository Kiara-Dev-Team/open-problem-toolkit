@testitem "Core Functionality" begin
    using HomomorphicCryptography

    @test greet isa Function
    @test length(available_schemes()) > 0
    @test scheme_info("Paillier") isa String
    @test security_recommendations() isa String
end

@testitem "Security Parameters - Standard" begin
    using HomomorphicCryptography

    params_128 = StandardSecurityParameters(SECURITY_128)
    @test params_128.security_level == SECURITY_128
    @test params_128.key_size == 2048

    params_192 = StandardSecurityParameters(SECURITY_192)
    @test params_192.security_level == SECURITY_192
    @test params_192.key_size == 3072
end

@testitem "Security Parameters - Paillier" begin
    using HomomorphicCryptography

    paillier_params = PaillierParameters(SECURITY_128)
    @test paillier_params.security_level == SECURITY_128
    @test paillier_params.key_size == 2048
    @test paillier_params.p_size == 1024
    @test paillier_params.q_size == 1024
    @test validate_parameters(paillier_params) == true
end
