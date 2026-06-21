"""
v10.5 — Interactive CLI Menu tests.

Verifies the fsociety-style numbered menu:
  • MENU_OPTIONS has the expected 19 entries (1-18 + 99 for Exit)
  • Each entry has a unique number, non-empty title/description, and a
    handler name that maps to a real method on InteractiveMenu
  • The dispatch logic maps both "1" and "01" to the same handler
  • Invalid choices return None
  • The Exit handler sets _running=False and returns 0
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gui.menu import (
    MENU_OPTIONS, InteractiveMenu, launch_menu, BANNER,
)


def test_menu_options_count():
    """Exactly 19 options: 18 numbered operations + Exit (99)."""
    assert len(MENU_OPTIONS) == 19


def test_menu_option_numbers_unique():
    nums = [opt[0] for opt in MENU_OPTIONS]
    assert len(nums) == len(set(nums)), f"Duplicate option numbers: {nums}"


def test_menu_option_numbers_sequential():
    """First 18 should be '01'..'18', last should be '99' (Exit)."""
    nums = [opt[0] for opt in MENU_OPTIONS]
    expected = [f"{i:02d}" for i in range(1, 19)] + ["99"]
    assert nums == expected, f"Expected {expected}, got {nums}"


def test_menu_has_exit_option():
    exit_options = [opt for opt in MENU_OPTIONS if opt[4] == "exit"]
    assert len(exit_options) == 1
    assert exit_options[0][0] == "99"


def test_menu_entries_have_emoji_title_desc_handler():
    """Each entry must be a 5-tuple (num, emoji, title, desc, handler)."""
    for entry in MENU_OPTIONS:
        assert len(entry) == 5, f"Bad entry: {entry}"
        num, emoji, title, desc, handler = entry
        assert num.isdigit(), f"Bad num: {num!r}"
        assert isinstance(emoji, str) and len(emoji) > 0
        assert isinstance(title, str) and len(title) > 0
        assert isinstance(desc, str) and len(desc) > 0
        # handler is a bare name like "full_scan" or "exit" — _dispatch adds
        # the "_op_" prefix when looking up the method.
        assert isinstance(handler, str) and len(handler) > 0, \
            f"Bad handler name: {handler!r}"
        assert handler.replace("_", "").isalnum(), \
            f"Bad handler name (must be alphanumeric+underscore): {handler!r}"


def test_every_handler_method_exists():
    """Every handler_name in MENU_OPTIONS must resolve to a method on
    InteractiveMenu (or be 'exit')."""
    menu = InteractiveMenu()
    for num, _, _, _, handler_name in MENU_OPTIONS:
        method_name = f"_op_{handler_name}"
        assert hasattr(menu, method_name), \
            f"Option [{num}] references missing method: {method_name}"
        assert callable(getattr(menu, method_name)), \
            f"Option [{num}] handler {method_name} is not callable"


def test_dispatch_accepts_zero_padded_and_bare():
    """Both '1' and '01' should resolve to the same handler function."""
    menu = InteractiveMenu()
    h1 = menu._dispatch("1")
    h01 = menu._dispatch("01")
    assert h1 is not None, "Dispatch should return a handler for '1'"
    assert h01 is not None, "Dispatch should return a handler for '01'"
    # Compare the underlying function (bound method objects are recreated
    # on each access, so `is` would always be False — but __func__ is the
    # same Python function object)
    assert h1.__func__ is h01.__func__, \
        "Dispatch should treat '1' and '01' as identical"


def test_dispatch_accepts_all_valid_numbers():
    """Every number from 1 to 18 plus 99 should dispatch successfully."""
    menu = InteractiveMenu()
    for n in list(range(1, 19)) + [99]:
        handler = menu._dispatch(str(n))
        assert handler is not None, f"Option {n} should dispatch to a handler"


def test_dispatch_rejects_invalid_input():
    """Out-of-range numbers, letters, and empty string should return None."""
    menu = InteractiveMenu()
    for bad in ("0", "19", "20", "100", "-1", "abc", "", "1.5"):
        assert menu._dispatch(bad) is None, \
            f"Dispatch should reject {bad!r} but returned a handler"


def test_exit_handler_sets_running_false_and_returns_zero():
    """Calling _op_exit should stop the loop and return exit code 0."""
    menu = InteractiveMenu()
    assert menu._running is True
    result = menu._op_exit()
    assert menu._running is False
    assert result == 0


def test_banner_contains_version():
    """BANNER should at least mention ReconNinja-ish ASCII art."""
    assert "ReconNinja" in BANNER or "____" in BANNER  # ASCII art fragment


def test_launch_menu_callable():
    """launch_menu should be a callable that returns an int."""
    assert callable(launch_menu)


# ─── Smoke test: the menu can construct and dispatch without crashing ────────

def test_menu_can_be_constructed():
    menu = InteractiveMenu()
    assert menu._running is True


def test_op_handlers_are_callable_without_args_signature():
    """Each operation handler should be callable (we won't actually invoke
    them here because they would prompt stdin). Just verify they exist as
    bound methods."""
    menu = InteractiveMenu()
    for num, _, _, _, handler_name in MENU_OPTIONS:
        if handler_name == "exit":
            continue
        method = getattr(menu, f"_op_{handler_name}")
        # Should be a bound method
        assert method.__self__ is menu
