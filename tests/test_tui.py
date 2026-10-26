from __future__ import annotations

import asyncio
from pathlib import Path
import re
import socket
import sys
import unittest
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from textual.widgets import Button, Input, RichLog, Select, Static, TextArea

from core.catalog import (
    ProfileCatalog,
    ProfileLeaf,
    QualificationStatus,
    TargetTrack,
    TrackDisposition,
)
from core.runplan import VerifierMode
from profiles import PROFILE_CATALOG
from tui import Php2ShellApp
from tui.app import RunOutputModal, execution_argv


def option_values(widget: Select) -> tuple[str, ...]:
    return tuple(
        str(value)
        for _label, value in widget._options
        if value is not Select.NULL
    )


IMGHAMMER_PALETTE = frozenset({
    "#000000",
    "#080d12",
    "#11161b",
    "#182129",
    "#1b3032",
    "#1b3638",
    "#202a33",
    "#2a343e",
    "#39504e",
    "#39534f",
    "#607480",
    "#607e77",
    "#71808b",
    "#758593",
    "#83e1c7",
    "#93a6b5",
    "#c7d1d9",
    "#e18b87",
})


class TuiTests(unittest.IsolatedAsyncioTestCase):
    async def _complete_candidate(
        self,
        app: Php2ShellApp,
        pilot,
        *,
        command: str = "id",
    ) -> None:
        app.query_one("#php-release", Select).value = "8.3.35"
        await pilot.pause()
        app.query_one("#runtime-product", Select).value = "docker-library/php"
        await pilot.pause()
        app.query_one("#architecture", Select).value = "arm64"
        await pilot.pause()
        app.query_one("#ini-contract", Select).value = "upstream-production"
        app.query_one("#target-url", Input).value = "http://lab.test/index.php"
        app.query_one("#command", Input).value = command
        await pilot.pause()
        self.assertIsNotNone(app.plan)

    async def test_only_run_and_quit_have_app_key_bindings(self) -> None:
        self.assertEqual(
            [(binding.key, binding.action) for binding in Php2ShellApp.BINDINGS],
            [("ctrl+r", "run"), ("ctrl+q", "quit")],
        )

        app = Php2ShellApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            self.assertEqual(
                str(app.query_one("#keymap", Static).content),
                "ctrl+r run   ctrl+q quit",
            )
            self.assertEqual(
                tuple(button.id for button in app.query("#action-row Button")),
                ("run", "review", "reset"),
            )

    def test_php2shell_palette_is_distinct_from_imghammer(self) -> None:
        source = (ROOT / "tui" / "app.py").read_text().lower()
        colors = set(re.findall(r"#[0-9a-f]{6}", source))
        self.assertFalse(
            colors & IMGHAMMER_PALETTE,
            f"shared imghammer colors: {sorted(colors & IMGHAMMER_PALETTE)}",
        )
        self.assertTrue({"#a98cff", "#5ee6f2", "#71e6b0"} <= colors)

    async def test_startup_is_offline_and_manifest_driven(self) -> None:
        app = Php2ShellApp()
        with (
            patch.object(socket, "create_connection", side_effect=AssertionError("network used")),
            patch(
                "tui.app.asyncio.create_subprocess_exec",
                side_effect=AssertionError("subprocess used"),
            ),
        ):
            async with app.run_test(size=(120, 36)) as pilot:
                await pilot.pause()
                self.assertEqual(len(app.screen_stack), 1)
                self.assertEqual(len(app.screen.query("#run-output")), 0)
                self.assertEqual(len(app.screen.query("#run-output-dialog")), 0)
                release = app.query_one("#php-release", Select)
                self.assertIs(release.value, Select.NULL)
                self.assertEqual(
                    option_values(release),
                    PROFILE_CATALOG.values("php_release"),
                )
                self.assertTrue(app.query_one("#sapi", Select).disabled)
                self.assertTrue(app.query_one("#runtime-product", Select).disabled)
                self.assertTrue(app.query_one("#architecture", Select).disabled)
                self.assertTrue(app.query_one("#ini-contract", Select).disabled)
                self.assertTrue(app.query_one("#workers", Input).disabled)
                self.assertTrue(app.query_one("#run", Button).disabled)
                self.assertTrue(app.query_one("#review", Button).disabled)
                self.assertIn("0/5 axes", str(app.query_one("#summary", Static).content))
                matrix = str(app.query_one("#matrix-status", Static).content)
                self.assertIn(
                    f"{len(PROFILE_CATALOG.tracks)} manifest/disposition tracks",
                    matrix,
                )
                badge = str(app.query_one("#scope-badge", Static).content)
                self.assertIn("PROFILE CATALOG", badge)
                self.assertNotIn("APACHE", badge.upper())

    async def test_run_output_modal_streams_large_then_closes_without_reset(self) -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        async def runner(plan, emit) -> int:
            emit("stage one is live")
            started.set()
            await release.wait()
            emit('{"outcome":"confirmed"}')
            return 0

        app = Php2ShellApp(runner=runner)
        async with app.run_test(size=(120, 36)) as pilot:
            await self._complete_candidate(app, pilot, command="whoami >/tmp/proof")
            frozen = app.plan
            self.assertIsNotNone(frozen)
            base_screen = app.screen

            try:
                await pilot.press("ctrl+r")
                await asyncio.wait_for(started.wait(), timeout=1.0)
                await pilot.pause()

                modal = app._output_modal
                self.assertIsInstance(modal, RunOutputModal)
                self.assertIs(app.screen, modal)
                self.assertEqual(len(app.screen_stack), 2)
                dialog = modal.query_one("#run-output-dialog")
                self.assertGreaterEqual(dialog.region.width, int(app.size.width * 0.85))
                self.assertGreaterEqual(dialog.region.height, int(app.size.height * 0.75))
                self.assertTrue(
                    modal.query_one("#close-run-output", Button).disabled
                )
                log = modal.query_one("#run-output", RichLog)
                visible = "\n".join(line.text for line in log.lines)
                self.assertIn("$ ", visible)
                self.assertIn("stage one is live", visible)
                self.assertIn("RUNNING", str(
                    modal.query_one("#run-output-status", Static).content
                ))
            finally:
                release.set()
                await app.workers.wait_for_complete()
                await pilot.pause()

            modal = app._output_modal
            self.assertIsInstance(modal, RunOutputModal)
            self.assertFalse(modal.query_one("#close-run-output", Button).disabled)
            self.assertIn(
                "COMPLETED · EXIT 0",
                str(modal.query_one("#run-output-status", Static).content),
            )
            self.assertEqual(app.plan, frozen)

            await pilot.click("#close-run-output")
            await pilot.pause()
            self.assertIs(app.screen, base_screen)
            self.assertEqual(len(app.screen_stack), 1)
            self.assertIsNone(app._output_modal)
            self.assertEqual(app.plan, frozen)
            self.assertEqual(
                app.query_one("#target-url", Input).value,
                "http://lab.test/index.php",
            )
            self.assertEqual(
                app.query_one("#command", Input).value,
                "whoami >/tmp/proof",
            )

    async def test_ctrl_r_runs_the_frozen_plan_and_streams_output(self) -> None:
        calls = []

        async def runner(plan, emit) -> int:
            calls.append(plan)
            emit("stage one")
            await asyncio.sleep(0)
            emit('{"outcome":"confirmed"}')
            return 0

        app = Php2ShellApp(runner=runner)
        async with app.run_test(size=(120, 36)) as pilot:
            await self._complete_candidate(app, pilot)
            frozen = app.plan
            self.assertIsNotNone(frozen)
            self.assertFalse(app.query_one("#run", Button).disabled)

            # Priority bindings must still fire while an Input owns focus.
            app.query_one("#command", Input).focus()
            await pilot.press("ctrl+r")
            await app.workers.wait_for_complete()
            await pilot.pause()

            self.assertEqual(calls, [frozen])
            self.assertEqual(
                app.run_transcript[-2:],
                ["stage one", '{"outcome":"confirmed"}'],
            )
            self.assertTrue(app.run_transcript[0].startswith("$ "))
            self.assertIn(
                "Run completed · exit 0",
                str(app.query_one("#run-hint", Static).content),
            )
            self.assertFalse(app.query_one("#run", Button).disabled)

    async def test_ctrl_r_refreezes_live_verifier_widgets_before_execution(self) -> None:
        calls = []

        async def runner(plan, emit) -> int:
            calls.append(plan)
            return 0

        app = Php2ShellApp(runner=runner)
        async with app.run_test(size=(120, 36)) as pilot:
            await self._complete_candidate(app, pilot)
            stale = app.plan
            self.assertIsNotNone(stale)
            self.assertIs(stale.verifier.mode, VerifierMode.NONE)

            # Model Ctrl+R overtaking queued Changed messages: the widgets hold
            # the new values while the cached plan is deliberately still NONE.
            verifier = app.query_one("#verifier-mode", Select)
            verify_path = app.query_one("#verify-path", Input)
            verify_text = app.query_one("#verify-text", Input)
            with verifier.prevent(Select.Changed):
                verifier.value = "http"
            with verify_path.prevent(Input.Changed):
                verify_path.value = "/proof.txt"
            with verify_text.prevent(Input.Changed):
                verify_text.value = "fresh-proof"

            self.assertIs(app.plan, stale)
            await pilot.press("ctrl+r")
            await app.workers.wait_for_complete()
            await pilot.pause()

            self.assertEqual(len(calls), 1)
            frozen = calls[0]
            self.assertIs(frozen.verifier.mode, VerifierMode.HTTP)
            self.assertEqual(frozen.verifier.path, "/proof.txt")
            self.assertEqual(frozen.verifier.expected_text, "fresh-proof")
            argv = execution_argv(frozen)
            self.assertEqual(argv[argv.index("--verify-path") + 1], "/proof.txt")
            self.assertEqual(argv[argv.index("--verify-text") + 1], "fresh-proof")

    async def test_second_ctrl_r_does_not_cancel_or_restart_active_run(self) -> None:
        started = asyncio.Event()
        release = asyncio.Event()
        calls = []

        async def runner(plan, emit) -> int:
            calls.append(plan)
            emit("started")
            started.set()
            await release.wait()
            emit("finished")
            return 0

        app = Php2ShellApp(runner=runner)
        async with app.run_test(size=(120, 36)) as pilot:
            await self._complete_candidate(app, pilot)
            try:
                await pilot.press("ctrl+r")
                await asyncio.wait_for(started.wait(), timeout=1.0)
                await pilot.press("ctrl+r")
                await pilot.pause()
                self.assertEqual(len(calls), 1)
                self.assertTrue(app._run_active)
            finally:
                release.set()
                await app.workers.wait_for_complete()
                await pilot.pause()

            self.assertEqual(len(calls), 1)
            self.assertIn("finished", app.run_transcript)

    async def test_ctrl_r_without_a_valid_plan_never_calls_runner(self) -> None:
        calls = []

        async def runner(plan, emit) -> int:
            calls.append(plan)
            return 0

        app = Php2ShellApp(runner=runner)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await pilot.press("ctrl+r")
            await pilot.pause()
            self.assertEqual(calls, [])
            self.assertIsNone(app._run_worker)
            self.assertIsNone(app._output_modal)
            self.assertEqual(len(app.screen_stack), 1)
            self.assertIn(
                "Complete a valid run draft",
                str(app.query_one("#run-hint", Static).content),
            )

    async def test_copy_and_reset_are_buttons_not_key_bindings(self) -> None:
        calls = []

        async def runner(plan, emit) -> int:
            calls.append(plan)
            return 0

        app = Php2ShellApp(runner=runner)
        async with app.run_test(size=(120, 36)) as pilot:
            await self._complete_candidate(app, pilot)
            expected = app.plan.shell_command() if app.plan is not None else ""
            with patch.object(app, "copy_to_clipboard") as copy:
                await pilot.click("#review")
                await pilot.pause()
                copy.assert_called_once_with(expected)
            self.assertEqual(calls, [])

            await pilot.click("#reset")
            await pilot.pause()
            self.assertIs(app.query_one("#php-release", Select).value, Select.NULL)
            self.assertEqual(app.query_one("#target-url", Input).value, "")
            self.assertEqual(app.query_one("#command", Input).value, "")
            self.assertIsNone(app.plan)
            self.assertEqual(app.run_transcript, [])
            self.assertEqual(calls, [])

    async def test_execution_argv_keeps_digest_and_command_as_exact_arguments(self) -> None:
        command = "whoami>/tmp/a2b2 && printf lol>/var/www/html/lol.txt"
        app = Php2ShellApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await self._complete_candidate(app, pilot, command=command)
            self.assertIsNotNone(app.plan)
            plan = app.plan
            argv = execution_argv(plan)

            self.assertEqual(argv[0], sys.executable)
            self.assertEqual(argv[1], "-u")
            self.assertTrue(Path(argv[2]).is_absolute())
            self.assertEqual(argv[argv.index("--profile-digest") + 1], plan.profile_digest)
            self.assertEqual(argv[argv.index("--cmd") + 1], command)
            self.assertEqual(argv.count(command), 1)
            self.assertNotIn("--workers", argv)

    async def test_default_runner_spawns_exact_argv_without_a_shell(self) -> None:
        class FakeStdout:
            def __init__(self) -> None:
                self.lines = iter((b"stage one\n", b"final line"))

            async def readline(self) -> bytes:
                return next(self.lines, b"")

        class FakeProcess:
            def __init__(self) -> None:
                self.stdout = FakeStdout()
                self.returncode = None

            async def wait(self) -> int:
                self.returncode = 7
                return 7

        app = Php2ShellApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await self._complete_candidate(app, pilot, command="id; echo still-one-arg")
            self.assertIsNotNone(app.plan)
            plan = app.plan
            process = FakeProcess()
            create = AsyncMock(return_value=process)
            emitted: list[str] = []

            with patch("tui.app.asyncio.create_subprocess_exec", create):
                exit_code = await app._run_subprocess(plan, emitted.append)

            self.assertEqual(exit_code, 7)
            self.assertEqual(emitted, ["stage one", "final line"])
            args, kwargs = create.await_args
            self.assertEqual(args, execution_argv(plan))
            self.assertEqual(kwargs["stdout"], asyncio.subprocess.PIPE)
            self.assertEqual(kwargs["stderr"], asyncio.subprocess.STDOUT)
            self.assertNotIn("shell", kwargs)
            self.assertNotIn("cwd", kwargs)

    async def test_all_five_axes_cascade_from_surviving_entries(self) -> None:
        app = Php2ShellApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.query_one("#php-release", Select).value = "8.4.26"
            await pilot.pause()
            self.assertEqual(
                app.query_one("#sapi", Select).value,
                "apache2handler-prefork",
            )
            product = app.query_one("#runtime-product", Select)
            self.assertFalse(product.disabled)
            self.assertEqual(
                option_values(product),
                PROFILE_CATALOG.values(
                    "runtime_product",
                    php_release="8.4.26",
                    sapi="apache2handler-prefork",
                ),
            )
            self.assertIn("docker-library/wordpress", option_values(product))

            product.value = "docker-library/wordpress"
            await pilot.pause()
            architecture = app.query_one("#architecture", Select)
            self.assertEqual(
                option_values(architecture),
                PROFILE_CATALOG.values(
                    "architecture",
                    php_release="8.4.26",
                    sapi="apache2handler-prefork",
                    runtime_product="docker-library/wordpress",
                ),
            )
            self.assertIn("arm64", option_values(architecture))

            architecture.value = "arm64"
            await pilot.pause()
            ini = app.query_one("#ini-contract", Select)
            self.assertEqual(
                set(option_values(ini)),
                {"wordpress-default", "wordpress-upstream-production"},
            )

    async def test_changing_release_clears_and_refilters_every_later_axis(self) -> None:
        app = Php2ShellApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            release = app.query_one("#php-release", Select)
            release.value = "8.3.35"
            await pilot.pause()
            product = app.query_one("#runtime-product", Select)
            product.value = "docker-library/php"
            await pilot.pause()
            architecture = app.query_one("#architecture", Select)
            self.assertEqual(option_values(architecture), ("amd64", "arm64"))
            architecture.value = "arm64"
            await pilot.pause()
            app.query_one("#ini-contract", Select).value = "upstream-production"
            await pilot.pause()

            release.value = "8.3.22"
            await pilot.pause()
            self.assertIs(product.value, Select.NULL)
            self.assertIs(architecture.value, Select.NULL)
            self.assertTrue(architecture.disabled)
            self.assertIs(app.query_one("#ini-contract", Select).value, Select.NULL)

            product.value = "docker-library/php"
            await pilot.pause()
            self.assertEqual(option_values(architecture), ("amd64",))

    async def test_exact_php_candidate_builds_a_worker_default_cli(self) -> None:
        app = Php2ShellApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.query_one("#php-release", Select).value = "8.3.35"
            await pilot.pause()
            app.query_one("#runtime-product", Select).value = "docker-library/php"
            await pilot.pause()
            app.query_one("#architecture", Select).value = "arm64"
            await pilot.pause()
            app.query_one("#ini-contract", Select).value = "upstream-production"
            app.query_one("#target-url", Input).value = "http://lab.test/index.php"
            app.query_one("#command", Input).value = "id"
            await pilot.pause()
            summary = str(app.query_one("#summary", Static).content)
            self.assertIn("CANDIDATE", summary)
            self.assertIn("modphp-pinned-v1/php-8.3.35-arm64-official", summary)
            self.assertIn("150 (profile default)", summary)
            self.assertNotIn("QUALIFICATION", summary)
            self.assertNotIn(app.resolution.profile.qualification_summary, summary)
            self.assertFalse(app.query_one("#review", Button).disabled)
            command = app.query_one("#command-preview", TextArea).text
            self.assertIn("--profile modphp-pinned-v1/php-8.3.35-arm64-official", command)
            self.assertIn("--profile-digest sha256:", command)
            self.assertNotIn("--workers", command)

    async def test_invalid_nonempty_worker_override_is_not_a_default(self) -> None:
        app = Php2ShellApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.query_one("#php-release", Select).value = "8.3.35"
            await pilot.pause()
            app.query_one("#runtime-product", Select).value = "docker-library/php"
            await pilot.pause()
            app.query_one("#architecture", Select).value = "arm64"
            await pilot.pause()
            app.query_one("#ini-contract", Select).value = "upstream-production"
            app.query_one("#target-url", Input).value = "http://lab.test/index.php"
            app.query_one("#command", Input).value = "id"
            app.query_one("#workers", Input).value = "-"
            await pilot.pause()

            self.assertTrue(app.query_one("#review", Button).disabled)
            preview = app.query_one("#command-preview", TextArea).text
            self.assertIn("positive integer", preview)
            self.assertNotIn("--cmd", preview)

    async def test_explicit_disposition_is_visible_but_not_runnable(self) -> None:
        target = TargetTrack(
            "8.4.26",
            "apache2handler-prefork",
            "docker-library/wordpress",
            "arm64",
            "wordpress-default",
            150,
            "test fixture",
        )
        disposition = TrackDisposition(
            target,
            QualificationStatus.REJECTED,
            "qualification failed",
            "campaign/test",
        )
        app = Php2ShellApp(ProfileCatalog(dispositions=(disposition,)))
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.query_one("#php-release", Select).value = "8.4.26"
            await pilot.pause()
            app.query_one("#runtime-product", Select).value = "docker-library/wordpress"
            await pilot.pause()
            app.query_one("#architecture", Select).value = "arm64"
            await pilot.pause()
            app.query_one("#ini-contract", Select).value = "wordpress-default"
            await pilot.pause()
            summary = str(app.query_one("#summary", Static).content)
            self.assertIn("REJECTED", summary)
            self.assertIn("qualification failed", summary)
            self.assertTrue(app.query_one("#review", Button).disabled)
            self.assertIn(
                "no supported",
                app.query_one("#command-preview", TextArea).text,
            )

    async def test_verifier_fields_and_responsive_layout(self) -> None:
        app = Php2ShellApp()
        async with app.run_test(size=(70, 24)) as pilot:
            await pilot.pause()
            self.assertTrue(app.screen.has_class("narrow"))
            self.assertTrue(app.query_one("#verify-path", Input).disabled)
            app.query_one("#verifier-mode", Select).value = "http"
            await pilot.pause()
            self.assertFalse(app.query_one("#verify-path", Input).disabled)
            self.assertFalse(app.query_one("#verify-text", Input).disabled)

    async def test_future_cli_leaf_has_generic_sapi_and_no_worker_field(self) -> None:
        target = TargetTrack(
            "8.4.26",
            "cli",
            "docker-library/php",
            "amd64",
            "no-main-ini",
        )
        profile = ProfileLeaf(
            target,
            "profile/cli",
            "sha256:" + "c" * 64,
            "php-build/cli",
            "runtime-bundle/cli",
            "sha256:" + "d" * 64,
            QualificationStatus.SUPPORTED,
            "test fixture",
        )
        app = Php2ShellApp(ProfileCatalog((profile,)))
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.query_one("#php-release", Select).value = "8.4.26"
            await pilot.pause()
            self.assertEqual(app.query_one("#sapi", Select).value, "cli")
            app.query_one("#runtime-product", Select).value = "docker-library/php"
            await pilot.pause()
            app.query_one("#architecture", Select).value = "amd64"
            await pilot.pause()
            app.query_one("#ini-contract", Select).value = "no-main-ini"
            await pilot.pause()
            summary = str(app.query_one("#summary", Static).content)
            self.assertIn("PHP CLI", summary)
            self.assertIn("not applicable", summary)
            self.assertTrue(app.query_one("#workers", Input).disabled)


if __name__ == "__main__":
    unittest.main()
