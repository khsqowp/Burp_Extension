"""Worker-mode logic invoked via main.py's `--introspect-tool` / `--run-tool`
sentinel args. The GUI process re-invokes *itself* (sys.executable -- which,
once frozen into proxy_scanner.exe, IS the exe, not a real python.exe) to get
a fresh, isolated child process for each introspection/run instead of relying
on a separately bundled Python interpreter. Works identically frozen or not.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys


def _load_tool_module(path: str):
    tool_dir = os.path.dirname(path)
    if tool_dir not in sys.path:
        sys.path.insert(0, tool_dir)
    spec = importlib.util.spec_from_file_location("_target_tool", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses etc. look themselves up via sys.modules
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def introspect_and_print(path: str) -> int:
    module = _load_tool_module(path)
    parser = module.build_arg_parser()
    actions = []
    for a in parser._actions:
        if a.dest == "help":
            continue
        default = a.default
        if not isinstance(default, (str, int, float, bool, type(None))):
            default = str(default)
        actions.append(
            {
                "dest": a.dest,
                "option_strings": a.option_strings,
                "help": a.help,
                "default": default,
                "choices": list(a.choices) if a.choices else None,
                "nargs": a.nargs,
                "required": bool(getattr(a, "required", False)),
                "action_type": type(a).__name__,
            }
        )
    print(json.dumps({"prog": parser.prog, "actions": actions}))
    return 0


def run_tool(path: str, argv: list[str]) -> int:
    module = _load_tool_module(path)
    return module.main(argv)
