using Test

# Include all source files
include("../src/PQCValidator.jl")
include("../src/HKDFHelpers.jl")
include("../src/ConfigLoader.jl")

using .PQCValidator
using .HKDFHelpers
using .ConfigLoader

@testset "PQCValidator.jl Tests" begin
    
    @testset "PQCValidator Core" begin
        @testset "Judgment struct" begin
            j = Judgment()
            @test !j.pass
            @test isempty(j.reasons)
            @test isempty(j.endpoint)
            @test !j.tls13
            @test isempty(j.named_group)
            @test j.kem_param == 0
            @test isempty(j.combiner)
        end
        
        @testset "Judgment operations" begin
            j = Judgment()
            pass!(j, "test pass")
            @test length(j.reasons) == 1
            @test startswith(j.reasons[1], "PASS:")
            
            fail!(j, "test fail")
            @test length(j.reasons) == 2
            @test startswith(j.reasons[2], "FAIL:")
            
            finalize!(j)
            @test !j.pass  # Should be false because we have a FAIL
            
            # Test all-pass scenario
            j2 = Judgment()
            pass!(j2, "test 1")
            pass!(j2, "test 2")
            finalize!(j2)
            @test j2.pass
        end
        
        @testset "JSON serialization" begin
            j = Judgment(pass=true, endpoint="test:443")
            json_str = to_json(j)
            @test occursin("\"pass\":true", json_str)
            @test occursin("\"endpoint\":\"test:443\"", json_str)
        end
    end
    
    @testset "HKDFHelpers" begin
        @testset "HKDF Extract" begin
            salt = fill(UInt8(0), 32)
            ikm = UInt8[1, 2, 3, 4]
            result = hkdf_extract(salt, ikm)
            @test length(result) == 32  # SHA-256 output length
            @test result isa Vector{UInt8}
        end
        
        @testset "HKDF Expand Label" begin
            prk = rand(UInt8, 32)
            label = "test"
            context = UInt8[]
            L = 16
            result = hkdf_expand_label(prk, label, context, L)
            @test length(result) == L
            @test result isa Vector{UInt8}
        end
        
        @testset "HKDF deterministic" begin
            # Same inputs should produce same outputs
            prk = fill(UInt8(42), 32)
            label = "test"
            context = UInt8[]
            L = 16
            
            result1 = hkdf_expand_label(prk, label, context, L)
            result2 = hkdf_expand_label(prk, label, context, L)
            @test result1 == result2
        end
    end
    
    @testset "ConfigLoader" begin
        @testset "Default config" begin
            # Test with non-existent file
            config = load_config("nonexistent.toml")
            @test config.endpoint_host == "example.com"
            @test config.endpoint_port == 443
            @test config.policy_kem_param == 768
            @test config.policy_combiner == "concat+kdf"
        end
        
        @testset "Config structure" begin
            config = Config()
            @test config.endpoint_host isa String
            @test config.endpoint_port isa Int
            @test config.tls_acceptable_groups isa Vector{String}
            @test config.policy_hash isa String
        end
    end
    
    @testset "Integration Tests" begin
        @testset "Config-based judgment" begin
            config = Config(policy_kem_param=1024, policy_combiner="test+kdf")
            j = Judgment()
            j.kem_param = config.policy_kem_param
            j.combiner = config.policy_combiner
            
            @test j.kem_param == 1024
            @test j.combiner == "test+kdf"
        end
    end
end