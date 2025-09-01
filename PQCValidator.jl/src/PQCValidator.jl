module PQCValidator

using JSON3, Dates

Base.@kwdef mutable struct Judgment
    pass::Bool = false
    reasons::Vector{String} = String[]
    endpoint::String = ""
    tls13::Bool = false
    named_group::String = ""
    kem_param::Int = 0
    combiner::String = ""
    artifacts::Dict{String,Any} = Dict()
    timestamp::String = string(Dates.now())
end

function pass!(j::Judgment, msg::String); push!(j.reasons, "PASS: " * msg); end
function fail!(j::Judgment, msg::String); push!(j.reasons, "FAIL: " * msg); end

function finalize!(j::Judgment)
    j.pass = all(startswith(r, "PASS:") for r in j.reasons) && !isempty(j.reasons)
    return j
end

function to_json(j::Judgment)
    JSON3.write(Dict(
        :pass => j.pass, :reasons => j.reasons, :endpoint => j.endpoint,
        :tls13 => j.tls13, :named_group => j.named_group,
        :kem_param => j.kem_param, :combiner => j.combiner,
        :artifacts => j.artifacts, :timestamp => j.timestamp
    ))
end

export Judgment, pass!, fail!, finalize!, to_json

end
