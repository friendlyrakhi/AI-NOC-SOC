# Hardened profile (P7): OpenBao with integrated (Raft) storage, single node, and TLS.
# Initialised and unsealed by openbao-setup. (OpenBao 2.x has no "file" storage backend.)
ui            = false
disable_mlock = true
api_addr      = "https://openbao:8200"
cluster_addr  = "https://openbao:8201"

storage "raft" {
  path    = "/openbao/file"
  node_id = "openbao-1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/run/secrets/openbao_tls_crt"
  tls_key_file    = "/run/secrets/openbao_tls_key"
  tls_min_version = "tls12"
}
