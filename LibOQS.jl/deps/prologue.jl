using Libdl: dlext
const liboqs =
    joinpath(pkgdir(@__MODULE__), "deps", "liboqs", "build", "lib", "liboqs.$(dlext)")
