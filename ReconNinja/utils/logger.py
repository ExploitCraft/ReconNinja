"""
ReconNinja v3 — Logger
Structured, thread-safe logging with Rich.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

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


def safe_print(*args, **kwargs) -> None:
    with _PRINT_LOCK:
        console.print(*args, **kwargs)


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
