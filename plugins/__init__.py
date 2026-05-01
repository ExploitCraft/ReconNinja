"""
ReconNinja v7.0.0 — Plugin System
Drop a .py file into plugins/ to extend ReconNinja automatically.

Plugin contract:
  - Module must define PLUGIN_NAME (str) and PLUGIN_VERSION (str)
  - Module must define a run(target, out_folder, result, config) function
  - Function receives ReconResult and ScanConfig; can mutate result in-place
  - Return value is ignored; errors should be caught internally

Example plugin skeleton (plugins/my_plugin.py):

    PLUGIN_NAME    = "my_plugin"
    PLUGIN_VERSION = "1.0"

    def run(target, out_folder, result, config):
        from pathlib import Path
        # Do something, append to result.errors / result.nuclei_findings etc.
        pass
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Callable

from utils.logger import log, safe_print
from utils.models import ReconResult, ScanConfig

PLUGINS_DIR = Path(__file__).parent


PluginFn = Callable[[str, Path, ReconResult, ScanConfig], None]


def _load_module(plugin_path: Path):
    spec = importlib.util.spec_from_file_location(plugin_path.stem, plugin_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[plugin_path.stem] = module
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module
    except Exception as e:
        log.warning(f"Failed to load plugin {plugin_path.name}: {e}")
        return None


def discover_plugins() -> list[tuple[str, PluginFn]]:
    """
    Walk the plugins/ directory, load valid plugins, return
    list of (name, run_fn) tuples.
    """
    plugins: list[tuple[str, PluginFn]] = []
    for py_file in sorted(PLUGINS_DIR.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        module = _load_module(py_file)
        if module is None:
            continue
        name = getattr(module, "PLUGIN_NAME", py_file.stem)
        run_fn = getattr(module, "run", None)
        if callable(run_fn):
            plugins.append((name, run_fn))
            log.debug(f"Plugin loaded: {name} v{getattr(module, 'PLUGIN_VERSION', '?')}")
        else:
            log.debug(f"Plugin {py_file.name} has no run() function — skipped")
    return plugins


def run_plugins(
    plugins: list[tuple[str, PluginFn]],
    target: str,
    out_folder: Path,
    result: ReconResult,
    config: ScanConfig,
) -> None:
    """Execute all loaded plugins against the current scan."""
    if not plugins:
        return

    safe_print(f"\n[module]⚙  Running {len(plugins)} plugin(s)...[/]")
    for name, fn in plugins:
        safe_print(f"[info]  → Plugin: {name}[/]")
        try:
            fn(target, out_folder, result, config)
            safe_print(f"[success]  ✔ {name} done[/]")
        except Exception as e:
            err = f"Plugin '{name}' error: {e}"
            log.warning(err)
            result.errors.append(err)
