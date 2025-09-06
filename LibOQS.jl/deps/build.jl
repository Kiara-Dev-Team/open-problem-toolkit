if !isdir("liboqs")
    run(
        `git clone --branch 0.14.0 --depth 1 https://github.com/open-quantum-safe/liboqs.git`,
    )
    run(`cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON`)
    run(`make -C liboqs/build -j`)
end

using Pkg;
Pkg.activate(@__DIR__)
Pkg.instantiate()

using Clang.Generators
using Clang.LibClang.Clang_jll

include_dir = normpath(joinpath(@__DIR__, "liboqs", "build", "include"))
options = load_options(joinpath(@__DIR__, "generator.toml"))

args = get_default_args()
push!(args, "-I$include_dir")

headers = [joinpath(include_dir, "oqs", "oqs.h")]

ctx = create_context(headers, args, options)
build!(ctx)
