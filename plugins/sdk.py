"""
ReconNinja v9 — Plugin SDK v2

@register decorator, ReconPlugin base class, community registry CLI.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from utils.logger import log, safe_print
from utils.models import ReconResult, ScanConfig

_PLUGIN_REGISTRY: dict[str, "PluginRegistration"] = {}


@dataclass
class PluginRegistration:
    name:        str
    version:     str
    author:      str
    description: str
    tags:        list[str]
    run_fn:      Callable
    phases:      list[str] = field(default_factory=list)
    requires:    list[str] = field(default_factory=list)


def register(
    name: str,
    version: str = "1.0.0",
    author: str = "",
    description: str = "",
    tags: list[str] | None = None,
    phases: list[str] | None = None,
    requires: list[str] | None = None,
):
    """
    Class decorator for Plugin SDK v2.

    Usage:
        @register(name="my_plugin", version="1.0.0", description="Does something cool")
        class MyPlugin(ReconPlugin):
            def run(self, target, out_folder, result, config):
                result.nuclei_findings.append(...)
    """
    def decorator(cls):
        if not issubclass(cls, ReconPlugin):
            raise TypeError(f"{cls.__name__} must subclass ReconPlugin")
        instance = cls()
        _PLUGIN_REGISTRY[name] = PluginRegistration(
            name=name, version=version, author=author, description=description,
            tags=tags or [], run_fn=instance.run,
            phases=phases or [], requires=requires or [],
        )
        log.debug(f"[plugin_sdk] Registered: {name} v{version}")
        return cls
    return decorator


class ReconPlugin:
    """Base class for all ReconNinja v9 plugins."""

    def run(self, target: str, out_folder: Path, result: ReconResult, config: ScanConfig) -> None:
        raise NotImplementedError

    def add_vuln(self, result, tool, severity, title, target, details="", cve=""):
        from utils.models import VulnFinding
        result.nuclei_findings.append(
            VulnFinding(tool=tool, severity=severity, title=title,
                        target=target, details=details, cve=cve)
        )

    def add_error(self, result, msg):
        result.errors.append(msg)

    def http_get(self, url, timeout=15):
        try:
            import requests as _requests
            return _requests.get(url, timeout=timeout, allow_redirects=True)
        except Exception:
            return None


PLUGINS_DIR = Path(__file__).parent
PluginFn = Callable[[str, Path, ReconResult, ScanConfig], None]


def _load_module(plugin_path: Path):
    spec = importlib.util.spec_from_file_location(plugin_path.stem, plugin_path)
    if not spec or not spec.loader:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[plugin_path.stem] = module
    try:
        spec.loader.exec_module(module)  # type: ignore
        return module
    except Exception as e:
        log.warning(f"[plugin_sdk] Load error {plugin_path.name}: {e}")
        return None


def discover_plugins() -> list[tuple[str, PluginFn]]:
    # Load all .py files to trigger @register decorators
    for py_file in sorted(PLUGINS_DIR.glob("*.py")):
        if py_file.name.startswith("_") or py_file.stem == "sdk":
            continue
        _load_module(py_file)

    discovered: list[tuple[str, PluginFn]] = [
        (reg.name, reg.run_fn) for reg in _PLUGIN_REGISTRY.values()
    ]

    # v8 fallback: PLUGIN_NAME + run()
    for py_file in sorted(PLUGINS_DIR.glob("*.py")):
        if py_file.name.startswith("_") or py_file.stem == "sdk":
            continue
        module = _load_module(py_file)
        if not module:
            continue
        name = getattr(module, "PLUGIN_NAME", None)
        run_fn = getattr(module, "run", None)
        if name and callable(run_fn) and name not in _PLUGIN_REGISTRY:
            discovered.append((name, run_fn))

    return discovered


def run_plugins(
    plugins: list[tuple[str, PluginFn]],
    target: str,
    out_folder: Path,
    result: ReconResult,
    config: ScanConfig,
) -> None:
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


def list_registry_plugins(registry_url: str) -> list[dict]:
    try:
        import requests
        resp = requests.get(f"{registry_url}/plugins.json", timeout=15)
        return resp.json().get("plugins", [])
    except Exception as e:
        log.warning(f"[plugin_sdk] Registry fetch failed: {e}")
        return []


def install_plugin(plugin_name: str, registry_url: str) -> bool:
    try:
        import requests
        plugins = list_registry_plugins(registry_url)
        plugin = next((p for p in plugins if p["name"] == plugin_name), None)
        if not plugin:
            safe_print(f"[danger]Plugin '{plugin_name}' not found in registry[/]")
            return False
        resp = requests.get(plugin["url"], timeout=30)
        dest = PLUGINS_DIR / f"{plugin_name}.py"
        dest.write_text(resp.text, encoding="utf-8")
        safe_print(f"[success]  ✔ Installed: {plugin_name} → {dest}[/]")
        return True
    except Exception as e:
        safe_print(f"[danger]Plugin install failed: {e}[/]")
        return False
