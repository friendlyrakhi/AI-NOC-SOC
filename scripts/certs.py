"""Local CA and service certificates for the `hardened` profile (P7, NFR-9).

    python scripts/certs.py            # creates what is missing in infrastructure/secrets/tls/
    python scripts/certs.py --rotate   # new leaf certificates (the CA is kept)
    python scripts/certs.py --new-ca   # new CA and leaves (clients must trust the new CA)

Dev-grade PKI: the CA key sits next to the certificates in the git-ignored secrets folder (ACL
restricted by bootstrap). Leaves are RSA-2048 (PKCS#8, accepted by Postgres, Valkey, ClickHouse,
OpenSearch, OpenBao, Node and Python), valid for 1 year, with the compose service name as SAN.
To use the platform in a browser over https://127.0.0.1:3443, trust ca.crt (see docs/operations).
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).resolve().parent.parent / "infrastructure" / "secrets" / "tls"
# service -> extra SANs (the service name itself is always included)
SERVICES: dict[str, list[str]] = {
    "postgres": [],
    "valkey": [],
    "clickhouse": [],
    "opensearch": [],
    "api": [],
    "ai-gateway": [],
    "openbao": [],
    "keycloak": ["localhost", "127.0.0.1"],
    "edge": ["localhost", "127.0.0.1"],
}


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NOC-SOC dev"), x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    )


def make_ca() -> None:
    key = _key()
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("NOC-SOC dev CA"))
        .issuer_name(_name("NOC-SOC dev CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=5 * 365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    (OUT / "ca.key").write_bytes(_pem_key(key))
    (OUT / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print("==> CA created")


def make_leaf(service: str, extra: list[str]) -> None:
    ca_key = serialization.load_pem_private_key((OUT / "ca.key").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((OUT / "ca.crt").read_bytes())
    key = _key()
    sans: list[x509.GeneralName] = []
    for name in [service, *extra]:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(service))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]
    )
    (OUT / f"{service}.key").write_bytes(_pem_key(key))
    (OUT / f"{service}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"==> certificate for {service}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rotate", action="store_true", help="re-issue every leaf certificate")
    p.add_argument("--new-ca", action="store_true", help="new CA (and leaves)")
    args = p.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if args.new_ca or not (OUT / "ca.crt").exists():
        make_ca()
        args.rotate = True
    for service, extra in SERVICES.items():
        if args.rotate or not (OUT / f"{service}.crt").exists():
            make_leaf(service, extra)
    print(f"certificates in {OUT}")


if __name__ == "__main__":
    main()
