import sys
from pathlib import Path

from crypto_core import (
    hybrid_encrypt_file,
    hybrid_encrypt_folder,
    hybrid_decrypt_file,
    hybrid_decrypt_folder,
    hybrid_decrypt_all,
)
from key_manager import generate_rsa_keypair


def print_usage():
    print("Usage:")
    print("  python main.py genkeys")
    print("  python main.py encrypt <path_to_file_or_folder>")
    print("  python main.py decrypt <base_filename> [folder_name] [output_folder]")
    print("  python main.py decrypt_folder <folder_name> [output_root]")
    print("  python main.py decrypt_all [output_root]")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "genkeys":
        generate_rsa_keypair()
        return

    if command == "encrypt":
        if len(sys.argv) < 3:
            print_usage()
            sys.exit(1)

        path_arg = sys.argv[2]
        p = Path(path_arg)

        if p.is_dir():
            print(f"encrypting: {p}")
            hybrid_encrypt_folder(path_arg)
            print(f"encrypted: {p}")
        elif p.is_file():
            print(f"encrypting: {p}")
            hybrid_encrypt_file(path_arg)
            print(f"encrypted: {p}")
        else:
            print(f"Path not found: {path_arg}")
        return

    if command == "decrypt":
        if len(sys.argv) < 3:
            print_usage()
            sys.exit(1)

        base_name = sys.argv[2]
        folder_name = sys.argv[3] if len(sys.argv) >= 4 else ""
        output_folder = sys.argv[4] if len(sys.argv) >= 5 else "decrypted_files"
        hybrid_decrypt_file(base_name, folder_name, output_folder)
        return

    if command == "decrypt_folder":
        if len(sys.argv) < 3:
            print_usage()
            sys.exit(1)

        folder_name = sys.argv[2]
        output_root = sys.argv[3] if len(sys.argv) >= 4 else "decrypted_files"
        hybrid_decrypt_folder(folder_name, output_root)
        return

    if command == "decrypt_all":
        output_root =_
