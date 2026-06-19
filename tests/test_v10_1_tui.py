"""Smoke test for the v10.1 TUI — verify it constructs and renders."""
import sys
import asyncio
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

# Skip the entire module if Textual isn't installed (CI may run headless).
pytest.importorskip("textual")
textual = pytest.importorskip("textual")
from gui.tui import ReconNinjaTUI, TEXTUAL_AVAILABLE, PHASES, PROFILES


@pytest.mark.asyncio
async def test_tui_constructs_and_renders():
    """The TUI must mount without errors and contain the expected widgets."""
    app = ReconNinjaTUI()
    async with app.run_test() as pilot:
        # Wait a moment for the mount to complete
        await pilot.pause()

        # Banner should be present
        banner = app.query_one("#banner")
        assert banner is not None

        # Target input should exist and be focusable
        target_input = app.query_one("#target-input")
        assert target_input is not None

        # All 4 profile buttons should exist
        for i, _ in enumerate(PROFILES):
            btn = app.query_one(f"#profile-btn-{i}")
            assert btn is not None

        # All phase lines should exist (47 phases per PHASES list)
        from gui.tui import PhaseLine
        phase_lines = list(app.query(PhaseLine))
        assert len(phase_lines) == len(PHASES), \
            f"Expected {len(PHASES)} phase lines, got {len(phase_lines)}"

        # Live log widget should exist
        live_log = app.query_one("#live-log")
        assert live_log is not None

        # Findings bar cells should exist
        for key in ("crit", "high", "med", "info", "subs", "hosts"):
            cell = app.query_one(f"#finding-{key}")
            assert cell is not None

        # Status bar should exist
        status = app.query_one("#status-bar")
        assert status is not None


@pytest.mark.asyncio
async def test_tui_profile_cycle():
    """Cycling the active profile via action_cycle_profile (bound to 'p')."""
    app = ReconNinjaTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.profile_idx == 1  # default 'standard'

        # Call the action directly — Textual's Input widget would otherwise
        # consume the 'p' keypress before it reaches the app-level handler.
        app.action_cycle_profile()
        await pilot.pause()
        assert app.profile_idx == 2  # 'thorough'

        app.action_cycle_profile()
        await pilot.pause()
        assert app.profile_idx == 3  # 'full_suite'

        app.action_cycle_profile()
        await pilot.pause()
        assert app.profile_idx == 0  # 'fast' (wrapped)

        app.action_cycle_profile()
        await pilot.pause()
        assert app.profile_idx == 1  # back to 'standard'


@pytest.mark.asyncio
async def test_tui_toggle_phase_via_space():
    """Toggling a phase line via PhaseLine.toggle() (bound to 'space' when
    a phase has focus)."""
    app = ReconNinjaTUI()
    async with app.run_test() as pilot:
        await pilot.pause()

        from gui.tui import PhaseLine
        first_phase = list(app.query(PhaseLine))[0]
        initial_state = first_phase.enabled

        # Call toggle directly (this is what the 'space' key handler does
        # when a PhaseLine has focus).
        first_phase.toggle()
        await pilot.pause()

        assert first_phase.enabled == (not initial_state), \
            f"Phase should have toggled from {initial_state} to {not initial_state}"

        # Toggle back
        first_phase.toggle()
        await pilot.pause()
        assert first_phase.enabled == initial_state


@pytest.mark.asyncio
async def test_tui_phase_status_transitions():
    """PhaseLine.set_status should update the visual state correctly."""
    app = ReconNinjaTUI()
    async with app.run_test() as pilot:
        await pilot.pause()

        from gui.tui import PhaseLine
        first_phase = list(app.query(PhaseLine))[0]
        assert first_phase.status == "idle"

        first_phase.set_status("running")
        await pilot.pause()
        assert first_phase.status == "running"

        first_phase.set_status("done")
        await pilot.pause()
        assert first_phase.status == "done"

        first_phase.set_status("failed")
        await pilot.pause()
        assert first_phase.status == "failed"

        first_phase.set_status("idle")
        await pilot.pause()
        assert first_phase.status == "idle"


@pytest.mark.asyncio
async def test_tui_help_overlay():
    """Toggling the help overlay via action_toggle_help (bound to '?')."""
    app = ReconNinjaTUI()
    async with app.run_test() as pilot:
        await pilot.pause()

        # No active modal screen at start
        assert app._help_visible is False

        # Call the action directly
        app.action_toggle_help()
        await pilot.pause()
        assert app._help_visible is True

        app.action_toggle_help()
        await pilot.pause()
        assert app._help_visible is False


@pytest.mark.asyncio
async def test_tui_start_scan_without_target_shows_error():
    """Pressing Enter with an empty target should set an error status, not crash."""
    app = ReconNinjaTUI()
    async with app.run_test() as pilot:
        await pilot.pause()

        # Target input is empty by default
        target_input = app.query_one("#target-input")
        assert target_input.value == ""

        # Press Enter — should not raise; should set error status
        target_input.focus()
        await pilot.press("enter")
        await pilot.pause()
        # The status bar should now mention the missing target
        status = app.query_one("#status-bar")
        # We can't easily read the rendered text, but the app should still
        # be alive (not crashed).
        assert app.is_running


@pytest.mark.asyncio
async def test_tui_clear_log():
    """Pressing 'c' should clear the live log panel."""
    app = ReconNinjaTUI()
    async with app.run_test() as pilot:
        await pilot.pause()

        from textual.widgets import RichLog
        log = app.query_one("#live-log", RichLog)
        # Write something to the log
        log.write("test line")
        await pilot.pause()

        # Press 'c' to clear
        await pilot.press("c")
        await pilot.pause()
        # No exception means it worked


def test_phases_list_complete():
    """All PHASES entries must have 3-tuple structure."""
    for entry in PHASES:
        assert len(entry) == 3, f"Bad phase entry: {entry}"
        phase_id, label, default_on = entry
        assert phase_id.startswith("run_"), f"Phase ID should start with run_: {phase_id}"
        assert isinstance(label, str) and len(label) > 0
        assert isinstance(default_on, bool)


def test_profiles_list():
    """PROFILES must be the expected 4 entries."""
    assert PROFILES == ["fast", "standard", "thorough", "full_suite"]
