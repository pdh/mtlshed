from typing import Dict, List, Any
import argparse


def add_all_arguments(parser: argparse.ArgumentParser) -> None:
    """Add all possible arguments to the parser"""

    # Common certificate configuration
    parser.add_argument("--config", type=str, help="Path to config file")
    parser.add_argument("--output-dir", default="./certs", help="Directory for certificates")
    parser.add_argument("-w", "--word-list-file", type=str, help="Word list file")
    parser.add_argument(
        "--key-size", type=int, default=2048, help="RSA key size (default: 2048)"
    )
    parser.add_argument(
        "--valid-days", type=int, default=365, help="Certificate validity in days"
    )

    # Certificate details
    parser.add_argument("--country", default="US", help="Certificate country")
    parser.add_argument("--state", default="State", help="Certificate state/province")
    parser.add_argument("--locality", default="Locality", help="Certificate locality")
    parser.add_argument(
        "--org", default="Organization", help="Certificate organization"
    )
    parser.add_argument(
        "--org-unit", default="Dev", help="Certificate organizational unit"
    )
    parser.add_argument(
        "--email", default="email@example.com", help="Certificate email"
    )

    # Client/Server configuration
    parser.add_argument(
        "--server-cn", default="server.local", help="Server common name"
    )
    parser.add_argument("--client-names", nargs="+", help="List of client names")
    parser.add_argument(
        "--client-passwords", nargs="+", help="List of client passwords"
    )
    parser.add_argument("--name", help="Certificate name for operations")

    # Import/Export options
    parser.add_argument("--public-key", help="Recipient's public key file")
    parser.add_argument("--private-key", help="Path to private key file")
    parser.add_argument("--input", help="Input file for operations")
    parser.add_argument("--output", help="Output file for operations")


def create_subparser_commands(
    subparsers: argparse._SubParsersAction,
) -> Dict[str, argparse.ArgumentParser]:
    """Create all subparser commands"""
    commands: Dict[str, Dict[str, str]] = {
        "create": {"help": "Create initial CA and certificates"},
        "add": {"help": "Add a new client"},
        "remove": {"help": "Remove a client"},
        "list": {"help": "List all certificates"},
        "info": {"help": "Get detailed certificate information"},
        "get-password": {"help": "Get client certificate password"},
        "export": {"help": "Export encrypted client certificate"},
        "decrypt": {"help": "Decrypt certificate data"},
        "tui": {"help": "Open the terminal user interface"},
    }

    parsers: Dict[str, argparse.ArgumentParser] = {}
    for cmd, attrs in commands.items():
        parser = subparsers.add_parser(cmd, help=attrs["help"])
        add_all_arguments(parser)
        parsers[cmd] = parser

    return parsers


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_all_arguments(parser)

    subparsers = parser.add_subparsers(dest="command", help="Commands")
    create_subparser_commands(subparsers)

    args = parser.parse_args()
    validate_args(args)

    return args


def validate_args(args: argparse.Namespace) -> None:
    """Validate required arguments based on command"""
    if not args.command:
        return

    # Define required arguments for each command
    required_args: Dict[str, List[str]] = {
        "export": ["name", "public-key", "output"],
        "decrypt": ["input", "private-key"],
        "info": ["name"],
        "get-password": ["name"],
        "add": ["client-names"],
        "remove": ["client-names"],
    }

    if args.command in required_args:
        missing = [
            arg
            for arg in required_args[args.command]
            if not getattr(args, arg.replace("-", "_"), None)
        ]
        if missing:
            raise argparse.ArgumentError(
                None,
                f"Command '{args.command}' requires these arguments: {', '.join(missing)}",
            )
