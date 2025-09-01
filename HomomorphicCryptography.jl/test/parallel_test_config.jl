# Parallel test configuration for ReTestItems.jl

# Test execution strategies
const FAST_TESTS = [:core, :fast, :compliance]
const MEDIUM_TESTS = [:paillier, :phe, :bfv, :fhe]
const SLOW_TESTS = [:elgamal, :slow]
const VERY_SLOW_TESTS = [:very_slow, :multiplication]

# Memory and timeout configuration
const DEFAULT_TIMEOUT = 60.0
const SLOW_TIMEOUT = 180.0
const VERY_SLOW_TIMEOUT = 300.0
const MEMORY_THRESHOLD = 0.8

# Parallel execution helper functions
function run_fast_tests()
    runtests(@__DIR__;
        verbose=true,
        nworkers=:auto,
        tags=FAST_TESTS,
        testitem_timeout=DEFAULT_TIMEOUT
    )
end

function run_medium_tests()
    runtests(@__DIR__;
        verbose=true,
        nworkers=2,  # Limit workers for memory-intensive tests
        tags=MEDIUM_TESTS,
        testitem_timeout=SLOW_TIMEOUT
    )
end

function run_slow_tests()
    runtests(@__DIR__;
        verbose=true,
        nworkers=1,  # Sequential for very slow tests
        tags=SLOW_TESTS,
        testitem_timeout=VERY_SLOW_TIMEOUT
    )
end

function run_all_tests_parallel()
    println("🚀 Running HomomorphicCryptography.jl Test Suite in Parallel")
    println("Available CPU cores: $(Threads.nthreads())")

    # Run fast tests first
    println("\n⚡ Running fast tests...")
    run_fast_tests()

    # Run medium tests
    println("\n🔧 Running medium tests...")
    run_medium_tests()

    # Run slow tests last
    println("\n🐌 Running slow tests...")
    run_slow_tests()

    println("\n✅ All tests completed!")
end
