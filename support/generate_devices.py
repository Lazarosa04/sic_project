"""support/generate_devices.py

Utility to generate multiple device (Node/Device) identities using the existing
CA manager. It will create certificates and private keys in `support/certs/`.

Usage examples:
  # Generate named devices (skip existing)
  ./venv/bin/python3 support/generate_devices.py --names "Node B,Node C,Node D,Node E"

  # Generate 3 devices named "node_1", "node_2", ...
  ./venv/bin/python3 support/generate_devices.py --count 3 --prefix "Device"

Notes:
  - The script will create the CA if missing (via gerar_ca_raiz()).
  - If a device file already exists (e.g. node_b_certificate.pem) the script
    will skip generating a new certificate for that friendly name.
"""

import os
import sys
import argparse
from typing import List

# Ensure project root is on sys.path so 'support' package imports work when the
# script is executed directly from the repository root.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

# Import from ca_manager
from support.ca_manager import gerar_ca_raiz, gerar_certificado_dispositivo, OUTPUT_DIR


def normalize_filename(name: str) -> str:
    return name.lower().replace(' ', '_')


def device_exists(name: str) -> bool:
    fname = f"{normalize_filename(name)}_certificate.pem"
    return os.path.exists(os.path.join(OUTPUT_DIR, fname))


def generate_named_devices(names: List[str], ou: str = 'IoT Node') -> None:
    # Ensure CA exists (generate or load)
    chave_ca, certificado_ca = gerar_ca_raiz()
    if chave_ca is None:
        raise RuntimeError('Failed to generate or load CA')

    for name in names:
        if device_exists(name):
            print(f"[SKIP] Identity for '{name}' already exists in {OUTPUT_DIR}/")
            continue

        print(f"[GEN] Generating identity for '{name}' (OU={ou})...")
        nid, _, _ = gerar_certificado_dispositivo(
            nome_amigavel=name,
            organizacao_unidade=ou,
            chave_ca=chave_ca,
            certificado_ca=certificado_ca
        )
        print(f"[OK] Generated {name} -> NID={nid}")


def generate_count(prefix: str, count: int, start_index: int = 1, ou: str = 'IoT Node') -> None:
    names = [f"{prefix} {i}" for i in range(start_index, start_index + count)]
    generate_named_devices(names, ou=ou)


def main():
    parser = argparse.ArgumentParser(description='Generate multiple device identities for SIC project')
    parser.add_argument('--names', help='Comma-separated friendly names (e.g. "Node B,Node C")')
    parser.add_argument('--count', type=int, help='Generate N devices using --prefix (e.g. --count 3 --prefix "Device")')
    parser.add_argument('--prefix', default='Node', help='Prefix used with --count to build names')
    parser.add_argument('--start', type=int, default=1, help='Start index for generated names (default 1)')
    parser.add_argument('--ou', default='IoT Node', help='Organizational Unit to put in certificate (default "IoT Node")')

    args = parser.parse_args()

    if not os.path.isdir(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    if args.names:
        names = [n.strip() for n in args.names.split(',') if n.strip()]
        if not names:
            print('[ERR] No names parsed from --names')
            return
        generate_named_devices(names, ou=args.ou)
        return

    if args.count and args.count > 0:
        generate_count(args.prefix, args.count, start_index=args.start, ou=args.ou)
        return

    parser.print_help()


if __name__ == '__main__':
    main()
