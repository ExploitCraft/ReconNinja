"""
ReconNinja v10.1 — Logger
Structured, thread-safe logging with Rich.

v10.1 addition: `_safe_print_hooks` lets the TUI capture safe_print output
without breaking the existing console.print behaviour for headless CLI use.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

THEME = Theme(
    {
        "info":           "bold cyan",
        "success":        "bold green",
        "warning":        "bold yellow",
        "danger":         "bold red",
        "header":         "bold magenta",
        "dim":            "dim white",
        "port.open":      "bold green",
        "port.filtered":  "yellow",
        "port.closed":    "red",
        "module":         "bold blue",
        "phase":          "bold white on blue",
    }
)

console = Console(theme=THEME)
_PRINT_LOCK = threading.Lock()
_RESULT_LOCK = threading.Lock()

# v10.1: subscribers that want to intercept safe_print output (e.g. the TUI's
# live log panel). Each hook is called with the rendered text string. Hooks
# are called inside _PRINT_LOCK so ordering is preserved.
_safe_print_hooks: list[Callable[[str], None]] = []


def add_safe_print_hook(hook: Callable[[str], None]) -> None:
    """Register a callable that receives every safe_print() rendered line.
    Used by the TUI to mirror console output into its RichLog widget."""
    _safe_print_hooks.append(hook)


def remove_safe_print_hook(hook: Callable[[str], None]) -> None:
    try:
        _safe_print_hooks.remove(hook)
    except ValueError:
        pass


def safe_print(*args, **kwargs) -> None:
    """Thread-safe print that also fans out to any registered hooks.

    The hooks receive a plain-text rendering (Rich markup stripped) so the
    TUI can re-style it as it likes. The console still gets the full Rich
    renderable for the headless CLI users.
    """
    with _PRINT_LOCK:
        # Render to console as usual
        console.print(*args, **kwargs)
        # Fan out to hooks (if any) with a stripped text version
        if _safe_print_hooks:
            try:
                from rich.text import Text
                t = Text(*args, **kwargs) if args else Text()
                plain = t.plain
            except Exception:
                plain = " ".join(str(a) for a in args)
            for hook in _safe_print_hooks:
                try:
                    hook(plain)
                except Exception:
                    pass


def setup_file_logger(log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("recon_ninja")
    logger.setLevel(logging.DEBUG)

    # Rich console handler (INFO+)
    ch = RichHandler(console=console, show_path=False, markup=True)
    ch.setLevel(logging.INFO)

    # File handler (DEBUG+)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    logger.handlers.clear()
    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


log = logging.getLogger("recon_ninja")
