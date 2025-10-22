### A Pluto.jl notebook ###
# v0.20.19

using Markdown
using InteractiveUtils

# ╔═╡ 11cfb05a-aefa-11f0-bb95-6fb5f8337028
begin
	using Test
	using LinearAlgebra
end

# ╔═╡ 6b038868-4ca5-4ae2-8988-35c7a47af784
begin
	struct GSOData{I<:Integer, F<:Real}
		B::Matrix{I}
		B⃗::Vector{F}
		Q::Matrix{F}
		R::Matrix{F}
	end
	
	function GSOData(B::AbstractMatrix)
		F = qr(B)
		R̃ = F.R
		for i in axes(R̃, 1)
			dᵢ = R̃[i, i]
			for j in i:size(R̃, 2)
				R̃[i, j] /= dᵢ
			end
		end
		Q̃ = F.Q * Diagonal(F.R)
		B⃗ = [dot((@view Q̃[:, j]), (@view Q̃[:, j])) for j in axes(Q̃, 2)]
		return GSOData(B, B⃗, Q̃, R̃)
	end
	
	function partial_size_reduce!(B, R, i::Int, j::Int)
		if !(i < j)
			throw(
				ArgumentError("should satisfy i < j, actual i=$(i), j=$(j)")
			)
		end
		μ_ij = R[i, j]
		q = round(BigInt, μ_ij)
		bi = @view B[:, i]
		bj = @view B[:, j]
		@. bj -= q * bi
		for l in 1:i
			R[l, j] -= q * R[l, i]
		end
		nothing
	end

	function partial_size_reduce!(g::GSOData, i::Int, j::Int)
		if !(i < j)
			throw(
				ArgumentError("should satisfy i < j, actual i=$(i), j=$(j)")
			)
		end
		partial_size_reduce!(g.B, g.R, i, j)
	end
	
	function size_reduce!(g::GSOData)
		R = g.R
		for j in 2:size(R, 2)
			for i in (j-1):-1:1
				partial_size_reduce!(g, i, j)
			end
		end
		g
	end
end

# ╔═╡ d6e34e0d-0bab-4f9a-bc64-1f74e26de2a1
function gsoupdate!(g::GSOData, k::Integer)
	k ≥ 2 || throw(ArgumentError("k should satisfy k ≥ 2, actual k=$(k)"))
	for i in axes(g.B, 1)
		# swap
		g.B[i, k-1], g.B[i, k] = g.B[i, k], g.B[i, k-1]
	end
	μ = g.R
	ν = μ[k-1, k]
	B = g.B⃗[k] + ν ^ 2 * g.B⃗[k-1]
	μ[k-1, k] = ν * g.B⃗[k - 1] / B
	g.B⃗[k] = g.B⃗[k] * g.B⃗[k-1] / B
	g.B⃗[k-1] = B
	for j = 1:(k-2)
		# swap
		μ[j, k-1], μ[j, k] =μ[j, k], μ[j, k-1]
	end
	n = size(μ, 2)
	for i = (k+1):n
		t = μ[k, i]
		μ[k, i] = μ[k-1, i] - ν * t
		μ[k-1, i] = t + μ[k-1, k] * μ[k, i]
	end
	g
end

# ╔═╡ 0e9e6154-5e1d-4a7a-920f-fc00a9b135ea
function LLL_reduce!(B::AbstractMatrix, δ::Real)
	if !(0.25 < δ < 1)
		throw(ArgumentError("Input δ must satisfy 0.25 < δ < 1"))
	end
	g = GSOData(B)
	k = 2
	n = size(g.B, 2)
	while k ≤ n
		for j = (k-1):-1:1
			partial_size_reduce!(g, j, k)
		end
		if g.B⃗[k] ≥ (δ - g.R[k-1, k] ^ 2) * g.B⃗[k-1]
			# Lovász 条件を満たす
			k += 1
		else
			# swap basis
			gsoupdate!(g, k)
			k = max(k-1, 2)
		end
	end
	g
end

# ╔═╡ 4b1ae1e4-a33a-421e-98d8-79f0febf4ed1
ℬ = [
	-696  -760 552 -160 307  117
	-186  -106 6   -429 -526 -94
	661   -775 9   -544 862  472
	-727   659 726  365 396  138
]

# ╔═╡ df5494e5-e134-4cb5-9a5e-f10376492078
function MLLL_reduce!(ℬ::AbstractMatrix{T}, δ::Float64) where {T}
	h = size(ℬ, 2)
	z = h
	g = 1
	Q = float(T).(ℬ)
	R = zeros(size(ℬ))
	for i in 1:min(size(R, 1), size(R, 2))
		R[i, i] = one(eltype(R))
	end
	B⃗ = zeros(size(ℬ, 2))
	while g ≤ z
		b_g = @view ℬ[:, g]
		if iszero(b_g)
			if g < z
				v = b_g
				b_z = @view ℬ[:, z]
				b_g .= b_z
				b_z .= v
			end
			z -= 1
		end
		b_g_ast = Q[:, g]
		for i = 1:(g-1)
			b_i_ast = @view Q[:, i]
			B_i = dot(b_i_ast, b_i_ast)			
			μ_ig = dot(b_g, b_i_ast) / B_i
			R[i, g] = μ_ig
			Q[:, g] .-= μ_ig .* b_i_ast
		end
		B⃗[g] = dot((@view Q[:, g]), (@view Q[:, g]))
		if g == 1
			g = 2
		else
			l = g
			k = g
			startagain = false
			while k ≤ l && !(startagain)
				partial_size_reduce!(ℬ, R, k-1, k)
				ν = R[k-1, k]
				B = B⃗[k] + ν^2 * B⃗[k-1]
				if B ≥ δ * B⃗[k-1]
					for j = (k-2):(-1):1
						partial_size_reduce!(ℬ, R, j, k)
					end
				else
					if iszero(ℬ[:, k])
						if k < z
							ℬ[:, z], ℬ[:, k] = ℬ[:, k], ℬ[:, z]
						end
						z -= 1
						g = k
						startagain = true
					else
						ℬ[:, k-1], ℬ[:, k] = ℬ[:, k], ℬ[:, k-1]
						for j = 1:k-2
							R[j, k], R[j, k-1] = R[j, k-1], R[j, k]
						end
						if B != 0
							if B⃗[k] ≈ 0
								B⃗[k] = B
								Q[:, k-1] = ν * Q[:, k-1]
								R[k-1,k] = inv(ν)
								for i = (k+1):l
									R[k-1, i] = R[k-1,i] / ν
								end
							else
								t = B⃗[k-1] / B
								R[k-1,k] = ν * t
								w = Q[:, k-1]
								Q[:, k-1] = Q[:, k] + ν * w
								B⃗[k-1] = B
								if k ≤ l
									Q[:, k] = -R[k-1, k] * Q[:, k] + (B⃗[k] / B) * w
									B⃗[k] = B⃗[k] * t
								end
								for i = (k+1):l
									t = R[k, i]
									R[k, i] = R[k-1, i] - ν * t
									R[k-1, i] = t + R[k-1, k] * R[k, i]
								end
							end
						else
							B⃗[k], B⃗[k-1] = B⃗[k-1], B⃗[k]
							Q[:, k], Q[:, k-1] = Q[:, k-1], Q[:, k]
							for i=(k+1):l
								t = R[k,i]
								R[k,i] = R[k-1,i] - ν * t
								R[k-1,i] = t + R[k-1,k] * R[k, i]
							end
						end
						k = max(k-1, 2)
					end
				end
			end
			if !(startagain)
				g += 1
			end
		end # if
	end # while
end # function

# ╔═╡ 86e5aa33-3eee-4da5-b10d-969b500c8a3c
begin
	δ = 0.75
	MLLL_reduce!(ℬ, δ)
end

# ╔═╡ 00000000-0000-0000-0000-000000000001
PLUTO_PROJECT_TOML_CONTENTS = """
[deps]
LinearAlgebra = "37e2e46d-f89d-539d-b4ee-838fcccc9c8e"
Test = "8dfed614-e22c-5e08-85e1-65c5234f0b40"
"""

# ╔═╡ 00000000-0000-0000-0000-000000000002
PLUTO_MANIFEST_TOML_CONTENTS = """
# This file is machine-generated - editing it directly is not advised

julia_version = "1.12.1"
manifest_format = "2.0"
project_hash = "daa57a5ae35ddc41f805b1b81e5a5b0171a8b179"

[[deps.Artifacts]]
uuid = "56f22d72-fd6d-98f1-02f0-08ddc0907c33"
version = "1.11.0"

[[deps.Base64]]
uuid = "2a0f44e3-6c83-55bd-87e4-b1978d98bd5f"
version = "1.11.0"

[[deps.CompilerSupportLibraries_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "e66e0078-7015-5450-92f7-15fbd957f2ae"
version = "1.3.0+1"

[[deps.InteractiveUtils]]
deps = ["Markdown"]
uuid = "b77e0a4c-d291-57a0-90e8-8db25a27a240"
version = "1.11.0"

[[deps.JuliaSyntaxHighlighting]]
deps = ["StyledStrings"]
uuid = "ac6e5ff7-fb65-4e79-a425-ec3bc9c03011"
version = "1.12.0"

[[deps.Libdl]]
uuid = "8f399da3-3557-5675-b5ff-fb832c97cbdb"
version = "1.11.0"

[[deps.LinearAlgebra]]
deps = ["Libdl", "OpenBLAS_jll", "libblastrampoline_jll"]
uuid = "37e2e46d-f89d-539d-b4ee-838fcccc9c8e"
version = "1.12.0"

[[deps.Logging]]
uuid = "56ddb016-857b-54e1-b83d-db4d58db5568"
version = "1.11.0"

[[deps.Markdown]]
deps = ["Base64", "JuliaSyntaxHighlighting", "StyledStrings"]
uuid = "d6f4376e-aef5-505a-96c1-9c027394607a"
version = "1.11.0"

[[deps.OpenBLAS_jll]]
deps = ["Artifacts", "CompilerSupportLibraries_jll", "Libdl"]
uuid = "4536629a-c528-5b80-bd46-f80d51c5b363"
version = "0.3.29+0"

[[deps.Random]]
deps = ["SHA"]
uuid = "9a3f8284-a2c9-5f02-9a11-845980a1fd5c"
version = "1.11.0"

[[deps.SHA]]
uuid = "ea8e919c-243c-51af-8825-aaa63cd721ce"
version = "0.7.0"

[[deps.Serialization]]
uuid = "9e88b42a-f829-5b0c-bbe9-9e923198166b"
version = "1.11.0"

[[deps.StyledStrings]]
uuid = "f489334b-da3d-4c2e-b8f0-e476e12c162b"
version = "1.11.0"

[[deps.Test]]
deps = ["InteractiveUtils", "Logging", "Random", "Serialization"]
uuid = "8dfed614-e22c-5e08-85e1-65c5234f0b40"
version = "1.11.0"

[[deps.libblastrampoline_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "8e850b90-86db-534c-a0d3-1478176c7d93"
version = "5.15.0+0"
"""

# ╔═╡ Cell order:
# ╠═11cfb05a-aefa-11f0-bb95-6fb5f8337028
# ╠═6b038868-4ca5-4ae2-8988-35c7a47af784
# ╠═d6e34e0d-0bab-4f9a-bc64-1f74e26de2a1
# ╠═0e9e6154-5e1d-4a7a-920f-fc00a9b135ea
# ╠═4b1ae1e4-a33a-421e-98d8-79f0febf4ed1
# ╠═df5494e5-e134-4cb5-9a5e-f10376492078
# ╠═86e5aa33-3eee-4da5-b10d-969b500c8a3c
# ╟─00000000-0000-0000-0000-000000000001
# ╟─00000000-0000-0000-0000-000000000002
