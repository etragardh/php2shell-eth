"""Command-line interface for the chain/profile plugin core."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from chains import CHAINS
from core.chain import RunContext
from core.catalog import QualificationStatus
from core.evidence import EvidenceWriter
from core.result import Outcome, RunResult
from core.target import Target
from profiles import PROFILE_CATALOG, PROFILE_LEAVES, PROFILES


RUNNABLE_PROFILE_STATUSES = frozenset((
    QualificationStatus.CANDIDATE,
    QualificationStatus.SUPPORTED,
))


def runnable_profile_ids() -> tuple[str, ...]:
    """Profiles explicitly allowed to reach a chain from the CLI."""
    return tuple(sorted(
        profile_id
        for profile_id, leaf in PROFILE_LEAVES.items()
        if leaf.status in RUNNABLE_PROFILE_STATUSES
    ))


def jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {key: jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


def build_parser(run_chain: object | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell-eth.py",
        description="Profile-driven PHP request-lifecycle PoC",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("tui", help="open the v2 target-contract navigator")
    subparsers.add_parser("chains", help="list available exploit chains")

    profiles = subparsers.add_parser("profiles", help="list active profile candidates")
    profiles.add_argument("--chain", choices=sorted(CHAINS))

    describe = subparsers.add_parser("describe", help="show one profile contract")
    describe.add_argument("profile", choices=sorted(PROFILES), metavar="PROFILE")

    run = subparsers.add_parser("run", help="run a chain selected by its profile")
    run.add_argument("target", help="absolute target URL, including request path")
    run.add_argument(
        "--profile",
        required=True,
        choices=runnable_profile_ids(),
        metavar="PROFILE",
        help="active profile id; use `profiles` to list candidates",
    )
    run.add_argument(
        "--profile-digest",
        help="optional exact manifest digest; mismatch aborts before network I/O",
    )
    run.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="per-stage socket timeout in seconds (default: 90)",
    )
    run.add_argument(
        "--evidence-dir",
        type=Path,
        help="new directory for response captures and run metadata",
    )
    if run_chain is not None:
        run_chain.add_arguments(run)
    return parser


def launch_tui() -> int:
    try:
        from tui import Php2ShellApp
    except ImportError as exc:
        print(
            "php2shell-eth.py: Textual 8 is required for the TUI; "
            "install the project dependencies or run the explicit CLI",
            file=sys.stderr,
        )
        return 2
    Php2ShellApp().run()
    return 0


def select_run_chain(argv: list[str]) -> object | None:
    if not argv or argv[0] != "run":
        return None
    if any(value in ("-h", "--help") for value in argv[1:]) and "--profile" not in argv:
        return None
    preflight = argparse.ArgumentParser(add_help=False)
    preflight.add_argument("target", nargs="?")
    preflight.add_argument(
        "--profile",
        required=True,
        choices=runnable_profile_ids(),
        metavar="PROFILE",
    )
    known, _unknown = preflight.parse_known_args(argv[1:])
    profile = PROFILES[known.profile]
    try:
        return CHAINS[profile.chain_id]
    except KeyError as exc:
        raise RuntimeError(
            f"profile {profile.id} names unavailable chain {profile.chain_id}"
        ) from exc


def result_record(
    result: RunResult,
    *,
    profile_digest: str | None = None,
    profile_status: QualificationStatus | None = None,
    effective_workers: int | None = None,
) -> dict[str, Any]:
    record = jsonable(result)
    if profile_digest is not None:
        record["execution_contract"] = {
            "profile_digest": profile_digest,
            "profile_status": profile_status.value if profile_status is not None else None,
            "effective_workers": effective_workers,
        }
    return record


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return launch_tui()

    run_chain = select_run_chain(argv)
    parser = build_parser(run_chain)
    args = parser.parse_args(argv)

    if args.command == "tui":
        return launch_tui()

    if args.command == "chains":
        for chain_id, chain in sorted(CHAINS.items()):
            print(f"{chain_id}\t{chain.summary}")
        return 0

    if args.command == "profiles":
        leaves = {leaf.profile_id: leaf for leaf in PROFILE_CATALOG.profiles}
        for profile_id, profile in sorted(PROFILES.items()):
            if args.chain is None or profile.chain_id == args.chain:
                status = leaves[profile_id].status.value
                print(f"{status}\t{profile_id}")
        return 0

    if args.command == "describe":
        profile = PROFILES[args.profile]
        chain = CHAINS[profile.chain_id]
        leaf = next(
            item for item in PROFILE_CATALOG.profiles
            if item.profile_id == profile.id
        )
        description = chain.describe_profile(profile)
        description["catalog"] = leaf
        print(json.dumps(jsonable(description), indent=2, sort_keys=True))
        return 0

    if args.command != "run" or run_chain is None:
        parser.print_help()
        return 2

    profile = PROFILES[args.profile]
    leaf = PROFILE_LEAVES[profile.id]
    if leaf.status not in RUNNABLE_PROFILE_STATUSES:
        parser.error(
            f"profile status {leaf.status.value!r} is not runnable; "
            "only candidate and supported profiles may execute"
        )
    actual_digest = leaf.profile_digest
    if args.profile_digest is not None and args.profile_digest != actual_digest:
        parser.error(
            "--profile-digest does not match the selected local profile; "
            "refresh the run plan"
        )
    try:
        target = Target.parse(args.target, timeout=args.timeout)
        evidence = EvidenceWriter(args.evidence_dir)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    context = RunContext(target=target, evidence=evidence)
    try:
        result = run_chain.run(context, profile, args)
    except (ConnectionError, OSError, TimeoutError) as exc:
        result = RunResult(
            profile.chain_id,
            profile.id,
            Outcome.TRANSPORT_ERROR,
            f"{type(exc).__name__}: {exc}",
        )
    effective_workers = (
        args.workers
        if args.workers is not None
        else profile.scheduler.default_workers if profile.scheduler is not None else None
    )
    evidence.write_json(
        "run.json",
        result_record(
            result,
            profile_digest=actual_digest,
            profile_status=leaf.status,
            effective_workers=effective_workers,
        ),
    )
    print(json.dumps({
        "chain": result.chain_id,
        "profile": result.profile_id,
        "outcome": result.outcome.value,
        "reason": result.reason,
    }, sort_keys=True))
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
