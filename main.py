import argparse
import os
import getpass
import logging
from crypto_tool import encrypt_file, decrypt_file

# Setup logging
logging.basicConfig(
    filename="encryption_log.txt",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def file_exists(path):
    return os.path.isfile(path)

def encrypt_cli(input_file, output_file):
    if not file_exists(input_file):
        print(f"[!] Error: File '{input_file}' does not exist.")
        return

    if os.path.exists(output_file):
        confirm = input(f"[!] Warning: '{output_file}' already exists. Overwrite? (y/n): ")
        if confirm.lower() != 'y':
            print("[*] Aborted.")
            return

    password = getpass.getpass("Enter password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("[!] Passwords do not match.")
        return

    try:
        encrypt_file(input_file, output_file, password)
        logging.info(f"Encrypted {input_file} -> {output_file}")
    except Exception as e:
        logging.error(str(e))
        print(f"[!] Error: {e}")

def decrypt_cli(input_file, output_file):
    if not file_exists(input_file):
        print(f"[!] Error: File '{input_file}' does not exist.")
        return

    if os.path.exists(output_file):
        confirm = input(f"[!] Warning: '{output_file}' already exists. Overwrite? (y/n): ")
        if confirm.lower() != 'y':
            print("[*] Aborted.")
            return

    password = getpass.getpass("Enter password: ")

    try:
        decrypt_file(input_file, output_file, password)
        logging.info(f"Decrypted {input_file} -> {output_file}")
    except Exception as e:
        logging.error(str(e))
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AES-256 File Encryptor")
    subparsers = parser.add_subparsers(dest="command")

    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("input", help="Path to input file")
    enc_parser.add_argument("output", help="Path to save encrypted file")

    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("input", help="Path to encrypted file")
    dec_parser.add_argument("output", help="Path to save decrypted file")

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypt_cli(args.input, args.output)
    elif args.command == "decrypt":
        decrypt_cli(args.input, args.output)
    else:
        parser.print_help()
