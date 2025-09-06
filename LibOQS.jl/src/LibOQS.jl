module LibOQS

using Libdl: dlext

include("C_API.jl")
using .C_API


end # module LibOQS
