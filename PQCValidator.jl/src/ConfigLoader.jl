module ConfigLoader

using TOML

Base.@kwdef struct Config
    endpoint_host::String = "example.com"
    endpoint_port::Int = 443
    endpoint_sni::String = ""
    
    tls_acceptable_groups::Vector{String} = ["X25519MLKEM768", "X25519:MLKEM768", "X25519Kyber768"]
    tls_force_group_arg::String = "X25519:MLKEM768"
    
    policy_kem_param::Int = 768
    policy_combiner::String = "concat+kdf"
    policy_hash::String = "SHA256"
end

function load_config(config_path::String="config.toml")
    config = Config()
    
    if !isfile(config_path)
        @warn "Config file '$config_path' not found, using defaults"
        return config
    end
    
    try
        toml_data = TOML.parsefile(config_path)
        
        # Parse endpoint section
        if haskey(toml_data, "endpoint")
            endpoint = toml_data["endpoint"]
            config = Config(
                endpoint_host = get(endpoint, "host", config.endpoint_host),
                endpoint_port = get(endpoint, "port", config.endpoint_port),
                endpoint_sni = get(endpoint, "sni", config.endpoint_host),
                
                tls_acceptable_groups = get(get(toml_data, "tls", Dict()), "acceptable_groups", config.tls_acceptable_groups),
                tls_force_group_arg = get(get(toml_data, "tls", Dict()), "force_group_arg", config.tls_force_group_arg),
                
                policy_kem_param = get(get(toml_data, "policy", Dict()), "kem_param", config.policy_kem_param),
                policy_combiner = get(get(toml_data, "policy", Dict()), "combiner", config.policy_combiner),
                policy_hash = get(get(toml_data, "policy", Dict()), "hash", config.policy_hash)
            )
        end
        
        # Override sni with host if sni is empty
        if isempty(config.endpoint_sni)
            config = Config(config; endpoint_sni = config.endpoint_host)
        end
        
    catch e
        @warn "Failed to parse config file '$config_path': $e. Using defaults."
    end
    
    return config
end

export Config, load_config

end