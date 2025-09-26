### A Pluto.jl notebook ###
# v0.20.6

using Markdown
using InteractiveUtils

# ╔═╡ 34d7da1e-fba7-47ac-aa89-4ab75c78d370
begin
	using Random
end

# ╔═╡ 7fcaa61c-98cc-11f0-337b-3d11213e98bd
md"""
ZKP: A toy model

本ノートブックは岡本, 太田. 暗号・ゼロ知識証明・数論 のプロトコル 0 の再現実装である．

大きな合成数 $n$ と $\mathrm{mod\ } n$ での平方剰余 $Z$ を与える．

```math
Z \equiv T^2 \mod n
```

となる $T$ を証明者 (Prover) $P$ が知っていることを検証者 (Validator) $V$ に示すプロトコル. 
"""

# ╔═╡ 9d033b0c-fb98-497c-ab84-859ab0f51528
md"""
Prover が実際に $Z \mod n$ の平方剰余を知っていれば次のようにして示すことができる
"""

# ╔═╡ c409b3a6-9f58-433f-b16f-4f85448adf2e
let
	n = BigInt(41141 * 41143)
	rng = Xoshiro(1234)
	T = rand(rng, 1:n) # prepare ground truth
	Z = T ^ 2
	outputs = map(1:10) do k
		# Prover P sends the following X to the Validator V
		R = rand(1:n)
		X = R ^ 2
		# V sends the following b to the P
		b = rand(Bool)
		# P sends the following Y to the V
		Y = if b
			T * R
		else
			R
		end
		#=
		V checks
		X ≡ Y² mod n if b = 0
		Z * X ≡ Y² mod n if b = 1
		=#
		if b
			mod(Z * X - Y^2, n) == 0
		else
			mod(X - Y^2, n) == 0
		end
	end

	if all(outputs)
		println("Prover knows T such that Z ≡ T² mod n")
	else
		println("Prover actually does not know T")
	end
end

# ╔═╡ a2a7e944-d36f-468d-840b-6637efa5a3fa
let
	n = BigInt(41141 * 41143)
	rng = Xoshiro(1234)
	_T = rand(rng, 1:n) # prepare ground truth
	Z = _T ^ 2
	
	T̃ = rand(rng, 1:n) # Prover prepares a random number
	outputs = map(1:10) do k
		# Prover P sends the following X to the Validator V
		R = rand(1:n)
		X = R ^ 2
		# V sends the following b to the P
		b = rand(Bool)
		# P sends the following Y to the V
		Y = if b
			T̃ * R # Prover P cheats
		else
			R
		end
		#=
		V checks
		X ≡ Y² mod n if b = 0
		Z * X ≡ Y² mod n if b = 1
		=#
		is_proven = if b
			mod(Z * X - Y^2, n) == 0
		else
			mod(X - Y^2, n) == 0
		end
	end

	if all(outputs)
		println("Prover knows T such that Z ≡ T² mod n")
	else
		println("Prover actually does not know T")
	end
end

# ╔═╡ 86013568-47b6-4c62-9d62-3e84b116e469
md"""
Validator が $T$ についての情報を欲しいので $b = true$ を常に送りつけた場合， Prover は次のようにして検証フェーズを突破できる． $Y_0$ をランダムに用意し $X \equiv Y_0 ^ 2 / Z \mod n$ を用意する． Validator におくる $Y$ として $Y=Y_0$ を設定する． 検証フェーズで 

```math
Z X \equiv Y^2 \mod n
```

が常に成り立つので Prover は検証フェーズを突破できる．
"""

# ╔═╡ 726bfb91-04e8-4c07-8452-1430344a16fb
let
	n = BigInt(41141 * 41143)
	rng = Xoshiro(1234)
	_T = rand(rng, 1:n) # prepare ground truth
	Z = mod(_T ^ 2, n)
	invZ = invmod(Z, n)
	@assert mod(Z * invZ, n) == 1
	
	outputs = map(1:10) do k
		# Prover P sends the following X to the Validator V
		Y0 = rand(1:n)
		X = mod(Y0^2 * invZ, n)
		# V sends the following b to the P
		b = true
		# P sends the following Y to the V
		Y = Y0
		#=
		V checks
		Z * X ≡ Y² mod n if b = 1
		=#
		is_proven = mod(Z * X - Y^2, n) == 0
	end

	if all(outputs)
		println("Prover knows T such that Z ≡ T² mod n")
	else
		println("Prover can't prove")
	end
end

# ╔═╡ 00000000-0000-0000-0000-000000000001
PLUTO_PROJECT_TOML_CONTENTS = """
[deps]
Random = "9a3f8284-a2c9-5f02-9a11-845980a1fd5c"
"""

# ╔═╡ 00000000-0000-0000-0000-000000000002
PLUTO_MANIFEST_TOML_CONTENTS = """
# This file is machine-generated - editing it directly is not advised

julia_version = "1.11.7"
manifest_format = "2.0"
project_hash = "fa3e19418881bf344f5796e1504923a7c80ab1ed"

[[deps.Random]]
deps = ["SHA"]
uuid = "9a3f8284-a2c9-5f02-9a11-845980a1fd5c"
version = "1.11.0"

[[deps.SHA]]
uuid = "ea8e919c-243c-51af-8825-aaa63cd721ce"
version = "0.7.0"
"""

# ╔═╡ Cell order:
# ╟─7fcaa61c-98cc-11f0-337b-3d11213e98bd
# ╠═34d7da1e-fba7-47ac-aa89-4ab75c78d370
# ╟─9d033b0c-fb98-497c-ab84-859ab0f51528
# ╠═c409b3a6-9f58-433f-b16f-4f85448adf2e
# ╠═a2a7e944-d36f-468d-840b-6637efa5a3fa
# ╟─86013568-47b6-4c62-9d62-3e84b116e469
# ╠═726bfb91-04e8-4c07-8452-1430344a16fb
# ╟─00000000-0000-0000-0000-000000000001
# ╟─00000000-0000-0000-0000-000000000002
