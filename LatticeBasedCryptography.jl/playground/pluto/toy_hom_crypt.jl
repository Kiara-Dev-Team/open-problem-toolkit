### A Pluto.jl notebook ###
# v0.20.10

using Markdown
using InteractiveUtils

# ╔═╡ 19b7f0f4-94ef-11f0-0ffd-03c05b78f10d
begin
	using Random
	
	using AbstractAlgebra
	using Distributions
end

# ╔═╡ cd927bc0-69b3-4202-87ca-13d103d00ea4
md"""
有田. [イデアル格子暗号入門](https://www.iisec.ac.jp/proc/vol0006/arita14.pdf) の準同型暗号を実装する．
"""

# ╔═╡ c68c74ea-f6dc-4e94-989f-194efdd45de8
begin
	q = 65
	P = 67
	σ = 2
	d = Normal(0, σ)
	ℤoverℤq, = residue_ring(ZZ, q) # ℤ/qℤ
	ℤoverℤPq, = residue_ring(ZZ, P * q) # ℤ/(Pq)ℤ
end

# ╔═╡ e5f0ed76-9b3a-4669-9f8c-fb33be246a50
R, ζ = let
	R, x = polynomial_ring(ZZ, :ζ)
	S, = residue_ring(R, x ^ 2 + x + 1)
	R, S(x)
end

# ╔═╡ 08dce129-ae70-4782-a0cd-495750046135
R_q, ζq = let
	R, x = polynomial_ring(ℤoverℤq, :ζq)
	S, = residue_ring(R, x ^ 2 + x + 1)
	R, S(x)
end

# ╔═╡ 4e45298c-9f1d-40fb-a640-b817bcec05ea
R_Pq, ζ_Pq = let
	R, x = polynomial_ring(ℤoverℤPq, :ζ_Pq)
	S, = residue_ring(R, x ^ 2 + x + 1)
	R, S(x)
end

# ╔═╡ d8709278-414f-4ff3-85d8-1c501e5eb8be
function generate_keys()
	s = rand(Bool) + rand(Bool)ζq
	a = rand(1:q) + rand(1:q)ζq
	e = round(Int, rand(d)) + round(Int, rand(d))ζq
	# cheating
	e = zero(ζq)
	b = a * s + 2 * e
	return(s, (a, b), e)
end

# ╔═╡ ae5e9371-e53f-4ea3-97f8-2c7c00db9e71
function enc(m, pk)
	v = rand(Bool) + rand(Bool)ζq
	e0 = round(Int, rand(d)) + round(Int, rand(d))ζq
	e1 = round(Int, rand(d)) + round(Int, rand(d))ζq

	# cheating
	e0 = zero(ζq)
	e1 = zero(ζq)

	a, b = pk
	
	c0 = b * v + 2 * e0 + m
	c1 = a * v + 2 * e1
	return (c0, c1)
end

# ╔═╡ c1f2a5e3-8407-43e3-86f8-d3a3851f1e63
function dec(c, sk)
	c0, c1 = c
	m̂ = c0 - sk * c1 
	return m̂
end

# ╔═╡ 1e19f118-214b-4165-909f-dc603b459061
begin
	function adjust_representation(element_Z, q=q)
		s = zero(ζ)
		for i in eachindex(element_Z.data.coeffs)
			s+= mod(
				element_Z.data.coeffs[i], ceil(Int, -q/2)+1:ceil(Int,q/2)
			) * ζ ^ (i-1)
		end
		s
	end
	
	function adjust_representation(element_Z::BigInt, q=q)
		return mod(element_Z, ceil(Int, -q/2)+1:ceil(Int,q/2))
	end
end

# ╔═╡ 56fcbbaa-0768-49a4-9630-6561af2f5934
begin
	function modq2modPq(elem_in_q)
		element_in_Pq = zero(ζ_Pq)
		for i in eachindex(elem_in_q.data.coeffs)
			element_in_Pq += elem_in_q.data.coeffs[i].data * ζ_Pq ^ (i-1)
		end
		return element_in_Pq
	end
	
	function Z2modPq(elem_in_Z)
		element_in_Pq = zero(ζ_Pq)
		for i in eachindex(elem_in_Z.data.coeffs)
			element_in_Pq += elem_in_Z.data.coeffs[i] * ζ_Pq ^ (i-1)
		end
		return element_in_Pq
	end

	function Z2modq(elem_in_Z)
		element_in_Pq = zero(ζq)
		for i in eachindex(elem_in_Z.data.coeffs)
			element_in_Pq += elem_in_Z.data.coeffs[i] * ζq ^ (i-1)
		end
		return element_in_Pq
	end

end

# ╔═╡ b975f0c6-7031-475e-a2c2-3979d6d50f46
begin
	function modqasZ(target)
		element_in_Z = zero(ζ)
		for i in eachindex(target.data.coeffs)
			element_in_Z += adjust_representation(target.data.coeffs[i].data) * ζ ^ (i-1)
		end
		return element_in_Z
	end

	function modPqasZ(target)
		element_in_Z = zero(ζ)
		for i in eachindex(target.data.coeffs)
			element_in_Z += adjust_representation(
				target.data.coeffs[i].data, P * q
			) * ζ ^ (i-1)
		end
		return element_in_Z
	end
end

# ╔═╡ 28a55e24-43e4-41e5-927d-6d8114b86994
let
	sk, pk = generate_keys()
	m = 1 + ζq
	c = enc(m, pk)
	m̂ = dec(c, sk)
	m̂ = adjust_representation(modqasZ(m̂))
	m̂0, m̂1 = m̂.data.coeffs
	@assert mod(m̂0, 2) + mod(m̂1, 2)ζq == m
end

# ╔═╡ 7e291995-3ca6-4f7c-92ac-b65d18284c76
# 暗号文同士の加法
let
	sk, pk = generate_keys()
	m = ζq
	m′ = ζq + 1
	c = enc(m, pk)
	c′ = enc(m′, pk)
	m̂ = dec(c .+ c′, sk)
	m̂ = adjust_representation(modqasZ(m̂))
	m_plus_m′ = m + m′

	for (m̂i, m_plus_m′i) in zip(m̂.data.coeffs, m_plus_m′.data.coeffs)
		@assert mod(m̂i, 2) == mod(m_plus_m′i.data, 2)
	end
end

# ╔═╡ 54fca652-f121-43e6-837b-5677687bbd2c
function modPq2modq(elem_in_Pq)
	element_in_q = zero(ζq)
	for i in eachindex(elem_in_Pq.data.coeffs)
		element_in_q += elem_in_Pq.data.coeffs[i].data * ζq ^ (i-1)
	end
	return element_in_q
end

# ╔═╡ 8af74ae7-7f19-4b15-8a16-e91f603fda26
function findδ(d) 
	δ0, δ1 = 0, 0
	δ⃗ = map(getproperty.(d.data.coeffs, :data)) do d
		δ = 0
		while true
			mod(d - δ, P) == 0 && break
			δ += 2
		end
		δ
	end	
	return sum(eachindex(δ⃗), init=0) do i
		δ = δ⃗[i]
		δ * ζ_Pq ^ (i-1)
	end
end

# ╔═╡ 85b6c8ca-8d82-429e-83ec-ceee44c39305
let
	sk, pk, e = generate_keys()
	sk_Pq = modq2modPq(sk)
	rng = Xoshiro(2025)
	A = rand(rng, 1:P * q) + rand(rng, 1:P * q)ζ_Pq
	
	sk_Pq = modq2modPq(sk)
	B_ = adjust_representation(modPqasZ(A), P * q) * modqasZ(sk) -P * modqasZ(sk ^ 2) + 2modqasZ(e)
	B = Z2modPq(B_)

	m = 1 + ζq
	m′ = ζq
	
	c = enc(m, pk)
	c′ = enc(m′, pk)

	c0, c1 = c
	c′0, c′1 = c′

	d0 = c0 * c′0
	d1 = c1 * c′0 + c0 * c′1
	d2 = -c1 * c′1

	d0_in_Z = adjust_representation(modPqasZ(d0))
	d1_in_Z = adjust_representation(modPqasZ(d1))
	d2_in_Z = adjust_representation(modPqasZ(d2))

	d′0_ = P * d0_in_Z + B_ * d2_in_Z
	d′0 = Z2modPq(d′0_)

	d′1_ = P * d1_in_Z + adjust_representation(modPqasZ(A), P * q) * d2_in_Z
	d′1 = Z2modPq(d′1_)

	d0′′_Pq = d′0 - findδ(d′0)
	d0′′_Pq.data.coeffs ./= P
	d0′′ = modPq2modq(d0′′_Pq)

	d1′′_Pq = d′1 - findδ(d′1)
	d1′′_Pq.data.coeffs ./= P
	d1′′ = modPq2modq(d1′′_Pq)

	m̂ = dec((d0′′, d1′′), sk)
	m̂ = adjust_representation(modqasZ(m̂))
	offset = ceil(Int, q / 2) + ceil(Int, q / 2)ζq
	mm′ = adjust_representation(modqasZ(m * m′))

	for (m̂i, mm′i) in zip(m̂.data.coeffs, mm′.data.coeffs)
		@assert mod(m̂i, 2) == mod(mm′i, 2)
	end
end

# ╔═╡ 76654c35-2128-4d6c-b67b-545c2dcc4438
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
	pk = (-19 - 8ζ, -9 - 21ζ)
	sk_Pq = modq2modPq(sk)
	e = 1 - ζq
	A = 2116 + 1119ζ_Pq
	B_ = modPqasZ(A) * modqasZ(sk) -P * modqasZ(sk ^ 2) + 2modqasZ(e)
	B = Z2modPq(B_)

	m = 1 + ζq
	m′ = ζq
	# c = enc(m, pk)
	# c′ = enc(m′, pk)
	c = (11 − 6ζq, −11 − 21ζq)
	c′ = (21 + 15ζq, 12 − 11ζq)

	c0, c1 = c
	c′0, c′1 = c′

	d0 = c0 * c′0
	@assert d0 == −4 − ζq
	d1 = c1 * c′0 + c0 * c′1
	@assert d1 == 20 − 30ζq
	d2 = -c1 * c′1
	@assert d2 == −27 − 28ζq

	d0_in_Z = adjust_representation(modPqasZ(d0))
	d1_in_Z = adjust_representation(modPqasZ(d1))
	d2_in_Z = adjust_representation(modPqasZ(d2))

	d′0_ = P * d0_in_Z + B_ * d2_in_Z
	d′0 = Z2modPq(d′0_)

	d′1_ = P * d1_in_Z + modPqasZ(A) * d2_in_Z
	d′1 = Z2modPq(d′1_)

	d0′′_Pq = d′0 - findδ(d′0)
	d0′′_Pq.data.coeffs ./= P
	d0′′ = modPq2modq(d0′′_Pq)

	d1′′_Pq = d′1 - findδ(d′1)
	d1′′_Pq.data.coeffs ./= P
	d1′′ = modPq2modq(d1′′_Pq)

	m̂ = dec((d0′′, d1′′), sk)

	m̂ = adjust_representation(modqasZ(m̂))
	m̂0, m̂1 = m̂.data.coeffs
	
	offset = ceil(Int, q / 2) + ceil(Int, q / 2)ζq
	mm′ = m * m′ - offset
	mm′0, mm′1 = mm′.data.coeffs
	m̂0, m̂1 = m̂.data.coeffs
	@assert mod(m̂0, 2) == mod(mm′0.data, 2)
	@assert mod(m̂1, 2) == mod(mm′1.data, 2)
end

# ╔═╡ 00000000-0000-0000-0000-000000000001
PLUTO_PROJECT_TOML_CONTENTS = """
[deps]
AbstractAlgebra = "c3fe647b-3220-5bb0-a1ea-a7954cac585d"
Distributions = "31c24e10-a181-5473-b8eb-7969acd0382f"
Random = "9a3f8284-a2c9-5f02-9a11-845980a1fd5c"

[compat]
AbstractAlgebra = "~0.47.3"
Distributions = "~0.25.120"
"""

# ╔═╡ 00000000-0000-0000-0000-000000000002
PLUTO_MANIFEST_TOML_CONTENTS = """
# This file is machine-generated - editing it directly is not advised

julia_version = "1.11.7"
manifest_format = "2.0"
project_hash = "5328beacb7103150be2bafb1018d378af777a499"

[[deps.AbstractAlgebra]]
deps = ["LinearAlgebra", "MacroTools", "Preferences", "Random", "RandomExtensions", "SparseArrays"]
git-tree-sha1 = "dc5edff637f5e6737128ea226c32fa242ebba3c0"
uuid = "c3fe647b-3220-5bb0-a1ea-a7954cac585d"
version = "0.47.3"

    [deps.AbstractAlgebra.extensions]
    TestExt = "Test"

    [deps.AbstractAlgebra.weakdeps]
    Test = "8dfed614-e22c-5e08-85e1-65c5234f0b40"

[[deps.AliasTables]]
deps = ["PtrArrays", "Random"]
git-tree-sha1 = "9876e1e164b144ca45e9e3198d0b689cadfed9ff"
uuid = "66dad0bd-aa9a-41b7-9441-69ab47430ed8"
version = "1.1.3"

[[deps.Artifacts]]
uuid = "56f22d72-fd6d-98f1-02f0-08ddc0907c33"
version = "1.11.0"

[[deps.CompilerSupportLibraries_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "e66e0078-7015-5450-92f7-15fbd957f2ae"
version = "1.1.1+0"

[[deps.DataAPI]]
git-tree-sha1 = "abe83f3a2f1b857aac70ef8b269080af17764bbe"
uuid = "9a962f9c-6df0-11e9-0e5d-c546b8b5ee8a"
version = "1.16.0"

[[deps.DataStructures]]
deps = ["OrderedCollections"]
git-tree-sha1 = "6c72198e6a101cccdd4c9731d3985e904ba26037"
uuid = "864edb3b-99cc-5e75-8d2d-829cb0a9cfe8"
version = "0.19.1"

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
git-tree-sha1 = "173e4d8f14230a7523ae11b9a3fa9edb3e0efd78"
uuid = "1a297f60-69ca-5386-bcde-b61e274b549b"
version = "1.14.0"
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

[[deps.IrrationalConstants]]
git-tree-sha1 = "e2222959fbc6c19554dc15174c81bf7bf3aa691c"
uuid = "92d709cd-6900-40b7-9082-c6be49f344b6"
version = "0.2.4"

[[deps.JLLWrappers]]
deps = ["Artifacts", "Preferences"]
git-tree-sha1 = "0533e564aae234aff59ab625543145446d8b6ec2"
uuid = "692b3bcd-3c85-4b1f-b108-f13ce0eb3210"
version = "1.7.1"

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

[[deps.MacroTools]]
git-tree-sha1 = "1e0228a030642014fe5cfe68c2c0a818f9e3f522"
uuid = "1914dd2f-81c6-5fcd-8719-6d5c9610ff09"
version = "0.5.16"

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
git-tree-sha1 = "0f27480397253da18fe2c12a4ba4eb9eb208bf3d"
uuid = "21216c6a-2e73-6563-6e65-726566657250"
version = "1.5.0"

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

[[deps.RandomExtensions]]
deps = ["Random", "SparseArrays"]
git-tree-sha1 = "b8a399e95663485820000f26b6a43c794e166a49"
uuid = "fb686558-2515-59ef-acaa-46db3789a887"
version = "0.4.4"

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
git-tree-sha1 = "64d974c2e6fdf07f8155b5b2ca2ffa9069b608d9"
uuid = "a2af1166-a08f-5f64-846c-94a0d3cef48c"
version = "1.2.2"

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
git-tree-sha1 = "2c962245732371acd51700dbb268af311bddd719"
uuid = "2913bbd2-ae8a-5f71-8c99-4fb6c76f3a91"
version = "0.34.6"

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

[[deps.Unicode]]
uuid = "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5"
version = "1.11.0"

[[deps.libblastrampoline_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "8e850b90-86db-534c-a0d3-1478176c7d93"
version = "5.11.0+0"
"""

# ╔═╡ Cell order:
# ╟─cd927bc0-69b3-4202-87ca-13d103d00ea4
# ╠═19b7f0f4-94ef-11f0-0ffd-03c05b78f10d
# ╠═c68c74ea-f6dc-4e94-989f-194efdd45de8
# ╠═e5f0ed76-9b3a-4669-9f8c-fb33be246a50
# ╠═08dce129-ae70-4782-a0cd-495750046135
# ╠═4e45298c-9f1d-40fb-a640-b817bcec05ea
# ╠═d8709278-414f-4ff3-85d8-1c501e5eb8be
# ╠═ae5e9371-e53f-4ea3-97f8-2c7c00db9e71
# ╠═c1f2a5e3-8407-43e3-86f8-d3a3851f1e63
# ╠═1e19f118-214b-4165-909f-dc603b459061
# ╠═28a55e24-43e4-41e5-927d-6d8114b86994
# ╠═7e291995-3ca6-4f7c-92ac-b65d18284c76
# ╠═56fcbbaa-0768-49a4-9630-6561af2f5934
# ╠═b975f0c6-7031-475e-a2c2-3979d6d50f46
# ╠═54fca652-f121-43e6-837b-5677687bbd2c
# ╠═8af74ae7-7f19-4b15-8a16-e91f603fda26
# ╠═85b6c8ca-8d82-429e-83ec-ceee44c39305
# ╠═76654c35-2128-4d6c-b67b-545c2dcc4438
# ╟─00000000-0000-0000-0000-000000000001
# ╟─00000000-0000-0000-0000-000000000002
