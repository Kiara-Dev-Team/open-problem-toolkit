### A Pluto.jl notebook ###
# v0.20.10

using Markdown
using InteractiveUtils

# ╔═╡ 93166e6a-942e-11f0-15f9-29ca327f2b20
begin
	using AbstractAlgebra
	using Distributions
end

# ╔═╡ 33676265-cc49-4a02-a325-0a51d06e7968
md"""
有田 [イデアル格子暗号入門](https://www.iisec.ac.jp/proc/vol0006/arita14.pdf) の Section 4.1 周りを Julia で実装する．
"""

# ╔═╡ b255a8e6-221c-49ee-865c-fa071e511937
begin
	q = 65
	σ = 2
	d = Normal(0, σ)
	ℤoverℤq, = residue_ring(ZZ, q) # ℤ/qℤ
	R = ℤoverℤq
end

# ╔═╡ aea0e012-bd85-4c79-9498-563035a2deec
ζ = let
	R, x = polynomial_ring(ℤoverℤq, :ζ)
	S, = residue_ring(R, x ^ 2 + x + 1)
	S(x)
end

# ╔═╡ 014bd8ef-86ca-495b-b3d1-179799f7dfc0
let
	# 例 4
	a = -19 - 8ζ
	s = 1 + ζ
	e = 1 - ζ
	b = a * s + e 
	@assert b == -10 - 20ζ
end

# ╔═╡ 0420e07e-0bba-4a04-ab6e-2fe432ab2a70
let
	# 例 5
	a = -19 - 8ζ
	s = 1 + ζ
	e = 1 - ζ
	b = a * s + 2e 
	@assert b == -9 - 21ζ
	@assert b - a * s == 2e
end

# ╔═╡ bc2c3645-26d5-4550-9bc9-245ba3bbb1e4
let
	# 例 6
	s = 1 + ζ
	a = -19 - 8ζ
	b = -9 - 21ζ
	m = 1 + ζ
	v = 1 + ζ
	e0 = -1 + ζ
	e1 = -ζ
	c0 = b * v + 2 * e0 + m
	c1 = a * v + 2 * e1

	m̂ = c0 - s * c1
	m̂0, m̂1 = m̂.data.coeffs
	@assert mod(m̂0.data, 2) + mod(m̂1.data, 2)ζ == m
end

# ╔═╡ c3d4d541-a6f8-43e1-bcdd-9d073c5841b7
let
	# 例 6
	s = 1 + ζ
	a = -19 - 8ζ
	b = -9 - 21ζ
	
	m′ = ζ
	v = ζ
	e0 = ζ
	e1 = 2
	c′0 = b * v + 2 * e0 + m′
	c′1 = a * v + 2 * e1
	@assert c′0 == 21 + 15ζ
	@assert c′1 == 12 - 11ζ

	m̂ = c′0 - s * c′1
	@assert m̂ == -2 + 3ζ
	offset = ceil(Int, q / 2) + ceil(Int, q / 2)ζ
	m̂ = m̂ - offset
	m̂0, m̂1 = m̂.data.coeffs 
	m̂0, m̂1
	mod(m̂0.data, 2) + mod(m̂1.data, 2)ζ
end

# ╔═╡ 9ceb00ed-7ca4-4384-bb96-86e0610203a1
function generate_keys()
	s = rand(Bool) + rand(Bool)ζ
	a = rand(1:q) + rand(1:q)ζ
	e = round(Int, rand(d)) + round(Int, rand(d))ζ
	b = a * s + 2 * e
	return(s, (a, b))
end

# ╔═╡ f3b67716-8394-4c85-afda-bcfe0e84686e
function enc(m, pk)
	v = rand(Bool) + rand(Bool)ζ
	e0 = round(Int, rand(d)) + round(Int, rand(d))ζ
	e1 = round(Int, rand(d)) + round(Int, rand(d))ζ
	a, b = pk
	c0 = b * v + 2 * e0 + m
	c1 = a * v + 2 * e1
	return (c0, c1)
end

# ╔═╡ 64945953-a5cd-42a5-935a-4742b5ed00ff
function dec(c, sk)
	c0, c1 = c
	m̂ = c0 - sk * c1 
	offset = ceil(Int, q / 2) + ceil(Int, q / 2)ζ
	return m̂ - offset
end

# ╔═╡ d9d4cfee-8cfb-440e-a717-46e88cf4205b
let
	sk, pk = generate_keys()
	m = 1 + ζ
	c = enc(m, pk)
	m̂ = dec(c, sk)
	m̂0, m̂1 = m̂.data.coeffs
	mod(m̂0.data, 2) + mod(m̂1.data, 2)ζ
end

# ╔═╡ 6681fd87-099f-481d-912d-97eca23f13ad
let
	sk, pk = generate_keys()
	m = ζ
	c = enc(m, pk)
	m̂ = dec(c, sk)
	m̂0, m̂1 = m̂.data.coeffs
	mod(m̂0.data, 2) + mod(m̂1.data, 2)ζ
end

# ╔═╡ 00000000-0000-0000-0000-000000000001
PLUTO_PROJECT_TOML_CONTENTS = """
[deps]
AbstractAlgebra = "c3fe647b-3220-5bb0-a1ea-a7954cac585d"
Distributions = "31c24e10-a181-5473-b8eb-7969acd0382f"

[compat]
AbstractAlgebra = "~0.47.3"
Distributions = "~0.25.120"
"""

# ╔═╡ 00000000-0000-0000-0000-000000000002
PLUTO_MANIFEST_TOML_CONTENTS = """
# This file is machine-generated - editing it directly is not advised

julia_version = "1.11.7"
manifest_format = "2.0"
project_hash = "8778c9246754fa81d15bde8bd76e324545b14375"

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
# ╟─33676265-cc49-4a02-a325-0a51d06e7968
# ╠═93166e6a-942e-11f0-15f9-29ca327f2b20
# ╠═b255a8e6-221c-49ee-865c-fa071e511937
# ╠═aea0e012-bd85-4c79-9498-563035a2deec
# ╠═014bd8ef-86ca-495b-b3d1-179799f7dfc0
# ╠═0420e07e-0bba-4a04-ab6e-2fe432ab2a70
# ╠═bc2c3645-26d5-4550-9bc9-245ba3bbb1e4
# ╠═c3d4d541-a6f8-43e1-bcdd-9d073c5841b7
# ╠═9ceb00ed-7ca4-4384-bb96-86e0610203a1
# ╠═f3b67716-8394-4c85-afda-bcfe0e84686e
# ╠═64945953-a5cd-42a5-935a-4742b5ed00ff
# ╠═d9d4cfee-8cfb-440e-a717-46e88cf4205b
# ╠═6681fd87-099f-481d-912d-97eca23f13ad
# ╟─00000000-0000-0000-0000-000000000001
# ╟─00000000-0000-0000-0000-000000000002
