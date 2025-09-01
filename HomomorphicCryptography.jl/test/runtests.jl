using ReTestItems

# Compatibility wrapper to absorb unsupported keywords (e.g., verbose)
const _ri_runtests = ReTestItems.runtests
function runtests(args...; verbose::Bool=false, kwargs...)
    _ri_runtests(args...; kwargs...)
end

# Include all test files
include("core_tests.jl")
include("paillier_tests.jl")
include("elgamal_tests.jl")
include("bfv_tests.jl")
include("serialization_tests.jl")
include("error_handling_tests.jl")
include("phase3_optimizations_tests.jl")

# Run all test items with parallel execution
nworkers = max(1, Sys.CPU_THREADS ÷ 2)  # Use half of available CPU cores
println("🚀 Running HomomorphicCryptography.jl tests with $nworkers workers")

runtests(@__DIR__;
    nworkers=nworkers,
    testitem_timeout=300.0,
    memory_threshold=0.8,
    verbose_results=true,
    nworker_threads=2,
)
