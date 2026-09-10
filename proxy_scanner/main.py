"""Entry point.
    python main.py                      -> launch the GUI (no args)
    python main.py --introspect-tool P  -> worker mode: print P's argparse
                                            definition as JSON (used by
                                            ToolTab to build its form)
    python main.py --run-tool P a b c   -> worker mode: run P's main(argv)
                                            in this (fresh, isolated) process
    python main.py --import-ca ...      -> worker mode: forwards to
                                            import_ca.py (see its docstring)

The worker sentinels exist so the frozen .exe can re-invoke *itself*
(sys.executable) to run/introspect the other tools -- there's no separately
bundled python.exe inside a PyInstaller onefile build.
"""
from __future__ import annotations

import sys

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# Logging is set up here (before anything else, including the worker
# sentinel dispatch below) so a crash during GUI import/startup is still
# caught -- spec: 개선작업 로그 기능 명세 §5.8. Worker-mode invocations
# (--introspect-tool/--run-tool) skip this: they're short-lived, run once
# per tool execution, and their own stdout/stderr already stream back to
# the GUI process that spawned them -- setting up a second rotating log
# file per worker process would just create lock contention on the shared
# proxy-scanner.log for no real benefit.
SESSION_ID = None
if len(sys.argv) < 2 or sys.argv[1] not in ("--introspect-tool", "--run-tool"):
    import app_logging

    SESSION_ID = app_logging.new_session_id()
    app_logging.setup_logging(SESSION_ID)
    app_logging.install_crash_hooks(SESSION_ID)
    app_logging.cleanup_expired_logs()


def _worker_dispatch() -> int | None:
    if len(sys.argv) >= 3 and sys.argv[1] == "--introspect-tool":
        from tool_worker import introspect_and_print

        return introspect_and_print(sys.argv[2])
    if len(sys.argv) >= 3 and sys.argv[1] == "--run-tool":
        from tool_worker import run_tool

        return run_tool(sys.argv[2], sys.argv[3:])
    if len(sys.argv) >= 1 and sys.argv[1:2] == ["--import-ca"]:
        import import_ca

        return import_ca.main(sys.argv[2:])
    if len(sys.argv) >= 1 and sys.argv[1:2] == ["--debug-tools-root"]:
        from tool_registry import TOOLS, TOOLS_ROOT

        print(f"TOOLS_ROOT = {TOOLS_ROOT}")
        for spec in TOOLS:
            print(f"  {spec.key}: {spec.script}  exists={spec.script.exists()}")
        return 0
    return None


if __name__ == "__main__":
    _code = _worker_dispatch()
    if _code is not None:
        raise SystemExit(_code)

    import gui

    raise SystemExit(gui.main(SESSION_ID))
