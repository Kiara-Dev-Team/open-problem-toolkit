### A Pluto.jl notebook ###
# v0.20.10

using Markdown
using InteractiveUtils

# ╔═╡ 96979f1d-72ca-4b63-b411-f28a8fa6acc5
begin
	using AbstractAlgebra
end

# ╔═╡ 5220f15e-8f8e-11f0-03be-3deea764f34e
md"""
# イデアル格子に入門する．

有田正剛 著 [イデアル格子暗号入門](https://www.iisec.ac.jp/proc/vol0006/arita14.pdf) の資料をもとにイデアル格子に入門する．
"""

# ╔═╡ 7bb50a4a-6d3f-4b73-8bc0-e97e225d7065
md"""
AbstractAlgebra パッケージを利用することで 1 の三乗根 $ζ ≠ 1$ を実現する．
"""

# ╔═╡ 5716e23e-7f80-448a-95dc-aac659004bf4
ζ = let
	R, x = polynomial_ring(ZZ, :ζ)
	S, = residue_ring(R, x ^ 2 + x + 1);
	S(x)
end

# ╔═╡ 8a4c968c-9580-46ea-8f79-379a50045ca1
let
	@assert ζ ≠ ζ ^ 2
	@assert ζ ^ 2 + ζ + 1 == 0
	@assert ζ ^ 3 == 1
	ξ = ζ + 1
	η = 3ζ + 1
	@assert ξ + η == 4ζ + 2
	# (a0 + a1ζ) · (b0 + b1ζ) = (a0b0 − a1b1) + (a0b1 + a1b0 − a1b1)ζ
	@assert ξ * η == ζ - 2
	a0 = ξ.data.coeffs[begin]
	a1 = ξ.data.coeffs[begin+1]
	b0 = η.data.coeffs[begin]
	b1 = η.data.coeffs[begin+1]
	ξ_η = ξ * η
	c0 = ξ_η.data.coeffs[begin]
	c1 = ξ_η.data.coeffs[begin+1]
	@assert c0 == a0 * b0 − a1 * b1 == -2
	@assert c1 == a0 * b1 + a1 * b0 − a1 * b1 == 1
end

# ╔═╡ f8e78701-ce4b-4bc6-92ec-d3952883162b
md"""
## 衝突困難関数の構成(n=2)

今回試す例は $n=2$ という小さい数値なので衝突困難ではない．$n = 2, m = 6, p = 5$ とする．$m$ 個の要素 $a_1, \dots, a_m \in \mathbb{Z}/p\mathbb{Z}[\zeta]$ を次のように選ぶ:
"""

# ╔═╡ b3132359-de4b-41cf-8d9d-54f2a6b3e213
begin
	n = 2
	m = 6
	p = 5
	a1 = 2 + 3ζ
	a2 = 4 + ζ
	a3 = 1 + 3ζ
	a4 = 1 + 0ζ
	a5 = 3 + 2ζ
	a6 = 2 + 2ζ

	function H(z1, z2, z3, z4, z5, z6)
		global p
		s = a1 * z1 + a2 * z2 + a3 * z3 + a4 * z4 + a5 * z5 + a6 * z6
		s.data.coeffs[begin] = mod(s.data.coeffs[begin], p)
		s.data.coeffs[begin + 1] = mod(s.data.coeffs[begin + 1], p)
		return s
	end

	z1 = 0 + ζ
	z2 = 1 + 0ζ
	z3 = 0 + 0ζ
	z4 = 1 + ζ
	z5 = 0 + ζ
	z6 = 1 + ζ

	w = H(z1, z2, z3, z4, z5, z6)
	# 011000110111 -> 001001 に圧縮している
end

# ╔═╡ 00000000-0000-0000-0000-000000000001
PLUTO_PROJECT_TOML_CONTENTS = """
[deps]
AbstractAlgebra = "c3fe647b-3220-5bb0-a1ea-a7954cac585d"

[compat]
AbstractAlgebra = "~0.47.3"
"""

# ╔═╡ 00000000-0000-0000-0000-000000000002
PLUTO_MANIFEST_TOML_CONTENTS = """
# This file is machine-generated - editing it directly is not advised

julia_version = "1.11.6"
manifest_format = "2.0"
project_hash = "dfb709a87f6215c4a3519882b21dc28d4522a615"

[[deps.AbstractAlgebra]]
deps = ["LinearAlgebra", "MacroTools", "Preferences", "Random", "RandomExtensions", "SparseArrays"]
git-tree-sha1 = "dc5edff637f5e6737128ea226c32fa242ebba3c0"
uuid = "c3fe647b-3220-5bb0-a1ea-a7954cac585d"
version = "0.47.3"

    [deps.AbstractAlgebra.extensions]
    TestExt = "Test"

    [deps.AbstractAlgebra.weakdeps]
    Test = "8dfed614-e22c-5e08-85e1-65c5234f0b40"

[[deps.Artifacts]]
uuid = "56f22d72-fd6d-98f1-02f0-08ddc0907c33"
version = "1.11.0"

[[deps.CompilerSupportLibraries_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "e66e0078-7015-5450-92f7-15fbd957f2ae"
version = "1.1.1+0"

[[deps.Dates]]
deps = ["Printf"]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"
version = "1.11.0"

[[deps.Libdl]]
uuid = "8f399da3-3557-5675-b5ff-fb832c97cbdb"
version = "1.11.0"

[[deps.LinearAlgebra]]
deps = ["Libdl", "OpenBLAS_jll", "libblastrampoline_jll"]
uuid = "37e2e46d-f89d-539d-b4ee-838fcccc9c8e"
version = "1.11.0"

[[deps.MacroTools]]
git-tree-sha1 = "1e0228a030642014fe5cfe68c2c0a818f9e3f522"
uuid = "1914dd2f-81c6-5fcd-8719-6d5c9610ff09"
version = "0.5.16"

[[deps.OpenBLAS_jll]]
deps = ["Artifacts", "CompilerSupportLibraries_jll", "Libdl"]
uuid = "4536629a-c528-5b80-bd46-f80d51c5b363"
version = "0.3.27+1"

[[deps.Preferences]]
deps = ["TOML"]
git-tree-sha1 = "0f27480397253da18fe2c12a4ba4eb9eb208bf3d"
uuid = "21216c6a-2e73-6563-6e65-726566657250"
version = "1.5.0"

[[deps.Printf]]
deps = ["Unicode"]
uuid = "de0858da-6303-5e67-8744-51eddeeeb8d7"
version = "1.11.0"

[[deps.Random]]
deps = ["SHA"]
uuid = "9a3f8284-a2c9-5f02-9a11-845980a1fd5c"
version = "1.11.0"

[[deps.RandomExtensions]]
deps = ["Random", "SparseArrays"]
git-tree-sha1 = "b8a399e95663485820000f26b6a43c794e166a49"
uuid = "fb686558-2515-59ef-acaa-46db3789a887"
version = "0.4.4"

[[deps.SHA]]
uuid = "ea8e919c-243c-51af-8825-aaa63cd721ce"
version = "0.7.0"

[[deps.Serialization]]
uuid = "9e88b42a-f829-5b0c-bbe9-9e923198166b"
version = "1.11.0"

[[deps.SparseArrays]]
deps = ["Libdl", "LinearAlgebra", "Random", "Serialization", "SuiteSparse_jll"]
uuid = "2f01184e-e22b-5df5-ae63-d93ebab69eaf"
version = "1.11.0"

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
# ╟─5220f15e-8f8e-11f0-03be-3deea764f34e
# ╠═96979f1d-72ca-4b63-b411-f28a8fa6acc5
# ╟─7bb50a4a-6d3f-4b73-8bc0-e97e225d7065
# ╠═5716e23e-7f80-448a-95dc-aac659004bf4
# ╠═8a4c968c-9580-46ea-8f79-379a50045ca1
# ╟─f8e78701-ce4b-4bc6-92ec-d3952883162b
# ╠═b3132359-de4b-41cf-8d9d-54f2a6b3e213
# ╟─00000000-0000-0000-0000-000000000001
# ╟─00000000-0000-0000-0000-000000000002
