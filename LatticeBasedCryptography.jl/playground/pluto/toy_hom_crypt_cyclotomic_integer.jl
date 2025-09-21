### A Pluto.jl notebook ###
# v0.20.8

using Markdown
using InteractiveUtils

# ╔═╡ d3ce97de-2cc3-472c-af94-d72f2a8d9b90
begin
	using Random
	using Distributions
end

# ╔═╡ 66f05352-9693-11f0-1512-b5a7123c732b
begin
	struct CyclotomicInteger{q} <: Number
		a::Int
		b::Int
		function CyclotomicInteger{q}(a, b) where q
			new(
				mod(a, (ceil(Int, -q/2)+1):ceil(Int, q/2)),
				mod(b, (ceil(Int, -q/2)+1):ceil(Int, q/2)),
			)
		end
	end

	function Base.show(io::IO, i::CyclotomicInteger{q}) where {q}
		println(io, "$(i.a) + $(i.b)ζ_$(q)")
	end
	
	function CyclotomicInteger{q}(x) where q
		CyclotomicInteger{q}(x, 0)
	end
	
	function Base.:+(u::CyclotomicInteger{q}, v::CyclotomicInteger{q}) where q
		return CyclotomicInteger{q}(u.a + v.a, u.b + v.b)
	end

	function Base.:-(u::CyclotomicInteger{q}, v::CyclotomicInteger{q}) where q
		return CyclotomicInteger{q}(u.a - v.a, u.b - v.b)
	end

	function Base.:-(u::CyclotomicInteger{q}) where q
		return CyclotomicInteger{q}(-u.a, -u.b)
	end

	function Base.:*(u::CyclotomicInteger{q}, v::CyclotomicInteger{q}) where q
		return CyclotomicInteger{q}(
			u.a * v.a - u.b * v.b,
			u.a * v.b + v.a * u.b - u.b * v.b,
		)
	end

	Base.promote_rule(::Type{CyclotomicInteger{q}}, ::Type{T}) where {q, T<:Integer} = CyclotomicInteger{q}
end

# ╔═╡ 727ca772-e580-46fd-8de6-97dc84aec41f
begin
	#q = 65
	#P = 67
	q = 1031	
	P = 1033	
	const ζq = CyclotomicInteger{q}(0, 1)
	Pq = P * q
	const ζ_Pq = CyclotomicInteger{Pq}(0, 1)
	const σ = 2.0
	const d = Normal(0, σ)
end

# ╔═╡ 5821289d-911a-4117-8ba9-67ebbad0c760
function generate_keys()
	s = rand(Bool) + rand(Bool)ζq
	e = round(Int, rand(d)) + round(Int, rand(d))ζq
	half_interval = (ceil(Int, -q/2)+1):ceil(Int, q/2)
	a = rand(half_interval) + rand(half_interval)ζq

	b = a * s + 2e
	return(s, (a, b), e)
end

# ╔═╡ 9b8c1a96-69c6-4c0d-aa0b-3d53d199723a
function enc(m, pk)
	v = rand(Bool) + rand(Bool)ζq
	e0 = round(Int, rand(d)) + round(Int, rand(d))ζq
	e1 = round(Int, rand(d)) + round(Int, rand(d))ζq
	a, b = pk
	c0 = b * v + 2 * e0 + m
	c1 = a * v + 2 * e1
	return (c0, c1)
end

# ╔═╡ 124ed143-a8c8-4bec-8479-99af57fbb35a
function findδ(d::CyclotomicInteger{Pq}) where Pq
	δ0, δ1 = 0, 0
	δ⃗ = map([d.a, d.b]) do d
		δplus = 0
		while true
			mod(d - δplus, P) == 0 && break
			δplus += 2
		end

		δminus = 0
		while true
			mod(d - δminus, P) == 0 && break
			δminus -= 2
		end
		
		if abs(δplus) > abs(δminus)
			δminus
		else
			δplus
		end
	end	
	ζ_Pq = CyclotomicInteger{Pq}(0, 1)
	return sum(eachindex(δ⃗), init=0) do i
		δ = δ⃗[i]
		δ * ζ_Pq ^ (i-1)
	end
end

# ╔═╡ 91eac559-e64e-4134-817f-84466f9a157e
function dec(c, sk)
	c0, c1 = c
	m̂ = c0 - sk * c1
	return m̂
end

# ╔═╡ 4c137804-6c18-4330-8a64-22ed0598e2bc
let
	sk, pk = generate_keys()
	m = 1 + ζq
	c = enc(m, pk)
	m̂ = dec(c, sk)
	@assert mod(m̂.a, 2) == mod(m.a, 2)
	@assert mod(m̂.b, 2) == mod(m.b, 2)
end

# ╔═╡ 37627bc6-3d2a-4e7c-81f6-e1ab6f4956ca
# 暗号文同士の加法
let
	sk, pk = generate_keys()
	m = ζq
	m′ = ζq + 1
	c = enc(m, pk)
	c′ = enc(m′, pk)
	m̂ = dec(c .+ c′, sk)
	m_plus_m′ = m + m′
	@assert mod(m̂.a, 2) == mod(m_plus_m′.a, 2)
	@assert mod(m̂.b, 2) == mod(m_plus_m′.b, 2)
end

# ╔═╡ 3f8ff4b3-9eb2-4fc1-8cfb-18415f7add66
let
	sk, pk, e = generate_keys()
	rng = Xoshiro(2025)
	half_interval_Pq = (ceil(Int, -Pq/2)+1):ceil(Int, Pq/2)
	A = rand(rng, half_interval_Pq) + rand(rng, half_interval_Pq)ζ_Pq
	sk_Pq = CyclotomicInteger{Pq}(sk.a, sk.b)
	e_Pq = CyclotomicInteger{Pq}(e.a, e.b)
	B = A * sk_Pq - P * sk_Pq * sk_Pq + 2 * e_Pq
	
	m = 1 + ζq
	m′ = ζq
	c = enc(m, pk)
	c′ = enc(m′, pk)

	c0, c1 = c
	c′0, c′1 = c′

	d0 = c0 * c′0
	d1 = c1 * c′0 + c0 * c′1
	d2 = -c1 * c′1

	d′0 = P * CyclotomicInteger{Pq}(d0.a, d0.b) + B * CyclotomicInteger{Pq}(d2.a, d2.b)

	d′1 = P * CyclotomicInteger{Pq}(d1.a, d1.b) + A * CyclotomicInteger{Pq}(d2.a, d2.b)

	d0′′_Pq = d′0 - findδ(d′0)
	@assert mod(d0′′_Pq.a, P) == 0
	@assert mod(d0′′_Pq.b, P) == 0
	d0′′ = CyclotomicInteger{q}(d0′′_Pq.a ÷ P, d0′′_Pq.b ÷ P)

	d1′′_Pq = d′1 - findδ(d′1)
	@assert mod(d1′′_Pq.a, P) == 0
	@assert mod(d1′′_Pq.b, P) == 0
	d1′′ = CyclotomicInteger{q}(d1′′_Pq.a ÷ P, d1′′_Pq.b ÷ P)

	m̂ = dec((d0′′, d1′′), sk)
	mm′ = m * m′
	@assert mod(m̂.a, 2) == mod(mm′.a, 2)
	@assert mod(m̂.b, 2) == mod(mm′.b, 2)
end

# ╔═╡ 73dadc71-bb77-46cd-9d98-2ec30ee718d3
let
	#=
	sk, pk = generate_keys()
	sk_Pq = modq2modPq(sk)
	
	minus_Ps² = -P * sk_Pq * sk_Pq
	A = rand(1:P * q) + rand(1:P * q)ζ_Pq
	e = round(Int, rand(d)) + round(Int, rand(d))ζ_Pq
	B = A * sk_Pq + minus_Ps² + 2e
	switch_key = (A, B)
	=#

	sk = 1 + ζq
	sk_Pq = CyclotomicInteger{Pq}(sk.a, sk.b)

	pk = (-19 - 8ζq, -9 - 21ζq)
	e = 1 - ζq
	e_Pq = CyclotomicInteger{Pq}(e.a, e.b)
	A = 2116 + 1119ζ_Pq
	B = A * sk_Pq - P * sk_Pq * sk_Pq + 2 * e_Pq
	
	m = 1 + ζq
	m′ = ζq
	# c = enc(m, pk)
	# c′ = enc(m′, pk)
	c = (11 − 6ζq, −11 − 21ζq)
	c′ = (21 + 15ζq, 12 − 11ζq)

	c0, c1 = c
	c′0, c′1 = c′

	d0 = c0 * c′0
	d1 = c1 * c′0 + c0 * c′1
	d2 = -c1 * c′1

	d′0 = P * CyclotomicInteger{Pq}(d0.a, d0.b) + B * CyclotomicInteger{Pq}(d2.a, d2.b)

	d′1 = P * CyclotomicInteger{Pq}(d1.a, d1.b) + A * CyclotomicInteger{Pq}(d2.a, d2.b)

	d0′′_Pq = d′0 - findδ(d′0)
	d0′′ = CyclotomicInteger{q}(d0′′_Pq.a ÷ P, d0′′_Pq.b ÷ P)

	d1′′_Pq = d′1 - findδ(d′1)
	d1′′ = CyclotomicInteger{q}(d1′′_Pq.a ÷ P, d1′′_Pq.b ÷ P)

	m̂ = dec((d0′′, d1′′), sk)
	mm′ = m * m′
	@assert mod(m̂.a, 2) == mod(mm′.a, 2)
	@assert mod(m̂.b, 2) == mod(mm′.b, 2)
end

# ╔═╡ 00000000-0000-0000-0000-000000000001
PLUTO_PROJECT_TOML_CONTENTS = """
[deps]
Distributions = "31c24e10-a181-5473-b8eb-7969acd0382f"
Random = "9a3f8284-a2c9-5f02-9a11-845980a1fd5c"

[compat]
Distributions = "~0.25.120"
"""

# ╔═╡ 00000000-0000-0000-0000-000000000002
PLUTO_MANIFEST_TOML_CONTENTS = """
# This file is machine-generated - editing it directly is not advised

julia_version = "1.11.7"
manifest_format = "2.0"
project_hash = "6472ec8577bb6a447088243756330f5c94875a37"

[[deps.AliasTables]]
deps = ["PtrArrays", "Random"]
git-tree-sha1 = "9876e1e164b144ca45e9e3198d0b689cadfed9ff"
uuid = "66dad0bd-aa9a-41b7-9441-69ab47430ed8"
version = "1.1.3"

[[deps.Artifacts]]
uuid = "56f22d72-fd6d-98f1-02f0-08ddc0907c33"
version = "1.11.0"

[[deps.Base64]]
uuid = "2a0f44e3-6c83-55bd-87e4-b1978d98bd5f"
version = "1.11.0"

[[deps.Compat]]
deps = ["TOML", "UUIDs"]
git-tree-sha1 = "8ae8d32e09f0dcf42a36b90d4e17f5dd2e4c4215"
uuid = "34da2185-b29b-5c13-b0c7-acf172513d20"
version = "4.16.0"
weakdeps = ["Dates", "LinearAlgebra"]

    [deps.Compat.extensions]
    CompatLinearAlgebraExt = "LinearAlgebra"

[[deps.CompilerSupportLibraries_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "e66e0078-7015-5450-92f7-15fbd957f2ae"
version = "1.1.1+0"

[[deps.DataAPI]]
git-tree-sha1 = "abe83f3a2f1b857aac70ef8b269080af17764bbe"
uuid = "9a962f9c-6df0-11e9-0e5d-c546b8b5ee8a"
version = "1.16.0"

[[deps.DataStructures]]
deps = ["Compat", "InteractiveUtils", "OrderedCollections"]
git-tree-sha1 = "4e1fe97fdaed23e9dc21d4d664bea76b65fc50a0"
uuid = "864edb3b-99cc-5e75-8d2d-829cb0a9cfe8"
version = "0.18.22"

[[deps.Dates]]
deps = ["Printf"]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"
version = "1.11.0"

[[deps.Distributions]]
deps = ["AliasTables", "FillArrays", "LinearAlgebra", "PDMats", "Printf", "QuadGK", "Random", "SpecialFunctions", "Statistics", "StatsAPI", "StatsBase", "StatsFuns"]
git-tree-sha1 = "3e6d038b77f22791b8e3472b7c633acea1ecac06"
uuid = "31c24e10-a181-5473-b8eb-7969acd0382f"
version = "0.25.120"

    [deps.Distributions.extensions]
    DistributionsChainRulesCoreExt = "ChainRulesCore"
    DistributionsDensityInterfaceExt = "DensityInterface"
    DistributionsTestExt = "Test"

    [deps.Distributions.weakdeps]
    ChainRulesCore = "d360d2e6-b24c-11e9-a2a3-2a2ae2dbcce4"
    DensityInterface = "b429d917-457f-4dbc-8f4c-0cc954292b1d"
    Test = "8dfed614-e22c-5e08-85e1-65c5234f0b40"

[[deps.DocStringExtensions]]
git-tree-sha1 = "7442a5dfe1ebb773c29cc2962a8980f47221d76c"
uuid = "ffbed154-4ef7-542d-bbb7-c09d3a79fcae"
version = "0.9.5"

[[deps.FillArrays]]
deps = ["LinearAlgebra"]
git-tree-sha1 = "6a70198746448456524cb442b8af316927ff3e1a"
uuid = "1a297f60-69ca-5386-bcde-b61e274b549b"
version = "1.13.0"
weakdeps = ["PDMats", "SparseArrays", "Statistics"]

    [deps.FillArrays.extensions]
    FillArraysPDMatsExt = "PDMats"
    FillArraysSparseArraysExt = "SparseArrays"
    FillArraysStatisticsExt = "Statistics"

[[deps.HypergeometricFunctions]]
deps = ["LinearAlgebra", "OpenLibm_jll", "SpecialFunctions"]
git-tree-sha1 = "68c173f4f449de5b438ee67ed0c9c748dc31a2ec"
uuid = "34004b35-14d8-5ef3-9330-4cdb6864b03a"
version = "0.3.28"

[[deps.InteractiveUtils]]
deps = ["Markdown"]
uuid = "b77e0a4c-d291-57a0-90e8-8db25a27a240"
version = "1.11.0"

[[deps.IrrationalConstants]]
git-tree-sha1 = "e2222959fbc6c19554dc15174c81bf7bf3aa691c"
uuid = "92d709cd-6900-40b7-9082-c6be49f344b6"
version = "0.2.4"

[[deps.JLLWrappers]]
deps = ["Artifacts", "Preferences"]
git-tree-sha1 = "a007feb38b422fbdab534406aeca1b86823cb4d6"
uuid = "692b3bcd-3c85-4b1f-b108-f13ce0eb3210"
version = "1.7.0"

[[deps.Libdl]]
uuid = "8f399da3-3557-5675-b5ff-fb832c97cbdb"
version = "1.11.0"

[[deps.LinearAlgebra]]
deps = ["Libdl", "OpenBLAS_jll", "libblastrampoline_jll"]
uuid = "37e2e46d-f89d-539d-b4ee-838fcccc9c8e"
version = "1.11.0"

[[deps.LogExpFunctions]]
deps = ["DocStringExtensions", "IrrationalConstants", "LinearAlgebra"]
git-tree-sha1 = "13ca9e2586b89836fd20cccf56e57e2b9ae7f38f"
uuid = "2ab3a3ac-af41-5b50-aa03-7779005ae688"
version = "0.3.29"

    [deps.LogExpFunctions.extensions]
    LogExpFunctionsChainRulesCoreExt = "ChainRulesCore"
    LogExpFunctionsChangesOfVariablesExt = "ChangesOfVariables"
    LogExpFunctionsInverseFunctionsExt = "InverseFunctions"

    [deps.LogExpFunctions.weakdeps]
    ChainRulesCore = "d360d2e6-b24c-11e9-a2a3-2a2ae2dbcce4"
    ChangesOfVariables = "9e997f8a-9a97-42d5-a9f1-ce6bfc15e2c0"
    InverseFunctions = "3587e190-3f89-42d0-90ee-14403ec27112"

[[deps.Markdown]]
deps = ["Base64"]
uuid = "d6f4376e-aef5-505a-96c1-9c027394607a"
version = "1.11.0"

[[deps.Missings]]
deps = ["DataAPI"]
git-tree-sha1 = "ec4f7fbeab05d7747bdf98eb74d130a2a2ed298d"
uuid = "e1d29d7a-bbdc-5cf2-9ac0-f12de2c33e28"
version = "1.2.0"

[[deps.OpenBLAS_jll]]
deps = ["Artifacts", "CompilerSupportLibraries_jll", "Libdl"]
uuid = "4536629a-c528-5b80-bd46-f80d51c5b363"
version = "0.3.27+1"

[[deps.OpenLibm_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "05823500-19ac-5b8b-9628-191a04bc5112"
version = "0.8.5+0"

[[deps.OpenSpecFun_jll]]
deps = ["Artifacts", "CompilerSupportLibraries_jll", "JLLWrappers", "Libdl"]
git-tree-sha1 = "1346c9208249809840c91b26703912dff463d335"
uuid = "efe28fd5-8261-553b-a9e1-b2916fc3738e"
version = "0.5.6+0"

[[deps.OrderedCollections]]
git-tree-sha1 = "05868e21324cede2207c6f0f466b4bfef6d5e7ee"
uuid = "bac558e1-5e72-5ebc-8fee-abe8a469f55d"
version = "1.8.1"

[[deps.PDMats]]
deps = ["LinearAlgebra", "SparseArrays", "SuiteSparse"]
git-tree-sha1 = "f07c06228a1c670ae4c87d1276b92c7c597fdda0"
uuid = "90014a1f-27ba-587c-ab20-58faa44d9150"
version = "0.11.35"

[[deps.Preferences]]
deps = ["TOML"]
git-tree-sha1 = "9306f6085165d270f7e3db02af26a400d580f5c6"
uuid = "21216c6a-2e73-6563-6e65-726566657250"
version = "1.4.3"

[[deps.Printf]]
deps = ["Unicode"]
uuid = "de0858da-6303-5e67-8744-51eddeeeb8d7"
version = "1.11.0"

[[deps.PtrArrays]]
git-tree-sha1 = "1d36ef11a9aaf1e8b74dacc6a731dd1de8fd493d"
uuid = "43287f4e-b6f4-7ad1-bb20-aadabca52c3d"
version = "1.3.0"

[[deps.QuadGK]]
deps = ["DataStructures", "LinearAlgebra"]
git-tree-sha1 = "9da16da70037ba9d701192e27befedefb91ec284"
uuid = "1fd47b50-473d-5c70-9696-f719f8f3bcdc"
version = "2.11.2"

    [deps.QuadGK.extensions]
    QuadGKEnzymeExt = "Enzyme"

    [deps.QuadGK.weakdeps]
    Enzyme = "7da242da-08ed-463a-9acd-ee780be4f1d9"

[[deps.Random]]
deps = ["SHA"]
uuid = "9a3f8284-a2c9-5f02-9a11-845980a1fd5c"
version = "1.11.0"

[[deps.Reexport]]
git-tree-sha1 = "45e428421666073eab6f2da5c9d310d99bb12f9b"
uuid = "189a3867-3050-52da-a836-e630ba90ab69"
version = "1.2.2"

[[deps.Rmath]]
deps = ["Random", "Rmath_jll"]
git-tree-sha1 = "852bd0f55565a9e973fcfee83a84413270224dc4"
uuid = "79098fc4-a85e-5d69-aa6a-4863f24498fa"
version = "0.8.0"

[[deps.Rmath_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl"]
git-tree-sha1 = "58cdd8fb2201a6267e1db87ff148dd6c1dbd8ad8"
uuid = "f50d1b31-88e8-58de-be2c-1cc44531875f"
version = "0.5.1+0"

[[deps.SHA]]
uuid = "ea8e919c-243c-51af-8825-aaa63cd721ce"
version = "0.7.0"

[[deps.Serialization]]
uuid = "9e88b42a-f829-5b0c-bbe9-9e923198166b"
version = "1.11.0"

[[deps.SortingAlgorithms]]
deps = ["DataStructures"]
git-tree-sha1 = "66e0a8e672a0bdfca2c3f5937efb8538b9ddc085"
uuid = "a2af1166-a08f-5f64-846c-94a0d3cef48c"
version = "1.2.1"

[[deps.SparseArrays]]
deps = ["Libdl", "LinearAlgebra", "Random", "Serialization", "SuiteSparse_jll"]
uuid = "2f01184e-e22b-5df5-ae63-d93ebab69eaf"
version = "1.11.0"

[[deps.SpecialFunctions]]
deps = ["IrrationalConstants", "LogExpFunctions", "OpenLibm_jll", "OpenSpecFun_jll"]
git-tree-sha1 = "41852b8679f78c8d8961eeadc8f62cef861a52e3"
uuid = "276daf66-3868-5448-9aa4-cd146d93841b"
version = "2.5.1"

    [deps.SpecialFunctions.extensions]
    SpecialFunctionsChainRulesCoreExt = "ChainRulesCore"

    [deps.SpecialFunctions.weakdeps]
    ChainRulesCore = "d360d2e6-b24c-11e9-a2a3-2a2ae2dbcce4"

[[deps.Statistics]]
deps = ["LinearAlgebra"]
git-tree-sha1 = "ae3bb1eb3bba077cd276bc5cfc337cc65c3075c0"
uuid = "10745b16-79ce-11e8-11f9-7d13ad32a3b2"
version = "1.11.1"
weakdeps = ["SparseArrays"]

    [deps.Statistics.extensions]
    SparseArraysExt = ["SparseArrays"]

[[deps.StatsAPI]]
deps = ["LinearAlgebra"]
git-tree-sha1 = "9d72a13a3f4dd3795a195ac5a44d7d6ff5f552ff"
uuid = "82ae8749-77ed-4fe6-ae5f-f523153014b0"
version = "1.7.1"

[[deps.StatsBase]]
deps = ["AliasTables", "DataAPI", "DataStructures", "LinearAlgebra", "LogExpFunctions", "Missings", "Printf", "Random", "SortingAlgorithms", "SparseArrays", "Statistics", "StatsAPI"]
git-tree-sha1 = "b81c5035922cc89c2d9523afc6c54be512411466"
uuid = "2913bbd2-ae8a-5f71-8c99-4fb6c76f3a91"
version = "0.34.5"

[[deps.StatsFuns]]
deps = ["HypergeometricFunctions", "IrrationalConstants", "LogExpFunctions", "Reexport", "Rmath", "SpecialFunctions"]
git-tree-sha1 = "8e45cecc66f3b42633b8ce14d431e8e57a3e242e"
uuid = "4c63d2b9-4356-54db-8cca-17b64c39e42c"
version = "1.5.0"

    [deps.StatsFuns.extensions]
    StatsFunsChainRulesCoreExt = "ChainRulesCore"
    StatsFunsInverseFunctionsExt = "InverseFunctions"

    [deps.StatsFuns.weakdeps]
    ChainRulesCore = "d360d2e6-b24c-11e9-a2a3-2a2ae2dbcce4"
    InverseFunctions = "3587e190-3f89-42d0-90ee-14403ec27112"

[[deps.SuiteSparse]]
deps = ["Libdl", "LinearAlgebra", "Serialization", "SparseArrays"]
uuid = "4607b0f0-06f3-5cda-b6b1-a6196a1729e9"

[[deps.SuiteSparse_jll]]
deps = ["Artifacts", "Libdl", "libblastrampoline_jll"]
uuid = "bea87d4a-7f5b-5778-9afe-8cc45184846c"
version = "7.7.0+0"

[[deps.TOML]]
deps = ["Dates"]
uuid = "fa267f1f-6049-4f14-aa54-33bafae1ed76"
version = "1.0.3"

[[deps.UUIDs]]
deps = ["Random", "SHA"]
uuid = "cf7118a7-6976-5b1a-9a39-7adc72f591a4"
version = "1.11.0"

[[deps.Unicode]]
uuid = "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5"
version = "1.11.0"

[[deps.libblastrampoline_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "8e850b90-86db-534c-a0d3-1478176c7d93"
version = "5.11.0+0"
"""

# ╔═╡ Cell order:
# ╠═d3ce97de-2cc3-472c-af94-d72f2a8d9b90
# ╠═66f05352-9693-11f0-1512-b5a7123c732b
# ╠═727ca772-e580-46fd-8de6-97dc84aec41f
# ╠═5821289d-911a-4117-8ba9-67ebbad0c760
# ╠═9b8c1a96-69c6-4c0d-aa0b-3d53d199723a
# ╠═124ed143-a8c8-4bec-8479-99af57fbb35a
# ╠═91eac559-e64e-4134-817f-84466f9a157e
# ╠═4c137804-6c18-4330-8a64-22ed0598e2bc
# ╠═37627bc6-3d2a-4e7c-81f6-e1ab6f4956ca
# ╠═3f8ff4b3-9eb2-4fc1-8cfb-18415f7add66
# ╠═73dadc71-bb77-46cd-9d98-2ec30ee718d3
# ╟─00000000-0000-0000-0000-000000000001
# ╟─00000000-0000-0000-0000-000000000002
