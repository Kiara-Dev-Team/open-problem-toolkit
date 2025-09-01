# Test setup and configuration for ReTestItems.jl

# Set test timeout (in seconds)
const TEST_TIMEOUT = 300  # 5 minutes for crypto operations

# Test configuration
const TEST_CONFIG = Dict(
    :verbose => true,
    :timeout => TEST_TIMEOUT,
    :retry => false,
    :parallel => true
)

# Helper functions for tests
function create_test_keypair(scheme_type, security_level=SECURITY_128)
    if scheme_type == :paillier
        scheme = PaillierScheme()
        params = PaillierParameters(security_level)
    elseif scheme_type == :elgamal
        scheme = ElGamalScheme()
        params = ElGamalParameters(security_level)
    elseif scheme_type == :bfv
        scheme = BFVScheme()
        params = LatticeParameters(security_level)
    else
        error("Unknown scheme type: $scheme_type")
    end

    return scheme, params, keygen(scheme, params)
end
