"""skedaddle-mcp: run the MCP server (default), or check from a shell / hook / CI.

  skedaddle-mcp                         MCP server on stdio
  skedaddle-mcp check npm axios@1.15.0  one package; JSON report on stdout
  skedaddle-mcp audit package-lock.json every exact pin in a lockfile
  skedaddle-mcp hook                    agent pre-install hook: hook JSON on stdin (Claude Code PreToolUse)
  skedaddle-mcp doctor [DIR]            which built-in package-manager protections are on, and how to turn them on
Exit: 0 allow, 1 warn, 2 block, 3 error (could not verify).
"""

from __future__ import annotations

import json
import sys

from . import __version__

EXIT = {"allow": 0, "warn": 1, "block": 2, "error": 3}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] == "serve":
        from .server import (
            main as serve,
        )  # imported lazily: check/audit need no MCP SDK

        serve()
        return 0
    if args[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0
    if args[0] == "hook":
        from .hook import main as hook

        return hook()
    if args[0] == "doctor":
        from .doctor import main as doctor

        return doctor(args[1:])
    if args[0] in ("-V", "--version"):
        print(__version__)
        return 0
    if args[0] == "check" and len(args) == 3:
        from .core import check_package, parse_spec

        try:
            name, version = parse_spec(args[1], args[2])
        except ValueError as e:
            print(json.dumps({"verdict": "error", "error": str(e)}))
            return 3
        rep = check_package(args[1], name, version).to_dict()
    elif args[0] == "audit" and len(args) == 2:
        from .lockfile import audit

        try:
            rep = audit(args[1])
        except (OSError, ValueError) as e:
            print(json.dumps({"verdict": "error", "error": str(e)}))
            return 3
    else:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    print(json.dumps(rep, indent=2, ensure_ascii=False))
    return EXIT.get(rep["verdict"], 3)


if __name__ == "__main__":
    sys.exit(main())
