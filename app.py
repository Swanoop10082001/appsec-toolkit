import argparse

from modules.headers import check_headers
from modules.jwt_decoder import decode_jwt
from modules.ssl_check import check_ssl
from modules.methods import check_methods
from modules.hash_identifier import identify_hash
from modules.password_checker import check_password
from modules.base64_tool import encode_base64, decode_base64
from modules.cvss import calculate_cvss


def banner():
    print("""
==========================================
        AppSec Toolkit v1.0
 Application Security Assessment Toolkit
==========================================
""")


def main():

    banner()

    parser = argparse.ArgumentParser()

    parser.add_argument("--headers")
    parser.add_argument("--jwt")
    parser.add_argument("--ssl")
    parser.add_argument("--methods")
    parser.add_argument("--hash")
    parser.add_argument("--password")
    parser.add_argument("--encode")
    parser.add_argument("--decode")
    parser.add_argument("--cvss")

    args = parser.parse_args()

    if args.headers:
        check_headers(args.headers)

    elif args.jwt:
        decode_jwt(args.jwt)

    elif args.ssl:
        check_ssl(args.ssl)

    elif args.methods:
        check_methods(args.methods)

    elif args.hash:
        identify_hash(args.hash)

    elif args.password:
        check_password(args.password)

    elif args.encode:
        encode_base64(args.encode)

    elif args.decode:
        decode_base64(args.decode)

    elif args.cvss:
        calculate_cvss(args.cvss)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
