from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.catalog import (
    ProfileCatalog,
    ProfileLeaf,
    QualificationStatus,
    SAPI_ID,
    TargetTrack,
    TrackDisposition,
    numeric_version_key,
)
from core.runplan import (
    PlanError,
    RunDraft,
    VerifierMode,
    WorkerSource,
    freeze_run_plan,
)
import cli
from profiles import MANIFESTS, PROFILE_CATALOG


def track(
    release: str = "8.4.26",
    *,
    sapi: str = SAPI_ID,
    product: str = "docker-library/php",
    architecture: str = "amd64",
    ini: str = "upstream-production",
    workers: int | None = 150,
) -> TargetTrack:
    return TargetTrack(
        release,
        sapi,
        product,
        architecture,
        ini,
        workers,
        "test fixture" if workers is not None else None,
    )


def leaf(
    target: TargetTrack,
    suffix: str,
    *,
    status: QualificationStatus = QualificationStatus.SUPPORTED,
    code_build: str = "php-build/test",
    runtime_bundle: str = "runtime-bundle/test",
) -> ProfileLeaf:
    digit = (suffix.encode("utf-8").hex() + "0" * 64)[:64]
    return ProfileLeaf(
        target,
        f"profile/{suffix}",
        "sha256:" + digit,
        code_build,
        runtime_bundle,
        "sha256:" + "b" * 64,
        status,
        "test fixture qualification",
    )


class V2CatalogTests(unittest.TestCase):
    def test_zero_arguments_always_dispatches_tui(self) -> None:
        with patch.object(cli, "launch_tui", return_value=17) as launch:
            self.assertEqual(cli.main([]), 17)
        launch.assert_called_once_with()

    def test_active_catalog_is_derived_only_from_discovered_manifests(self) -> None:
        tracks = PROFILE_CATALOG.tracks
        self.assertEqual(len(tracks), len(MANIFESTS))
        self.assertEqual(len(PROFILE_CATALOG.profiles), len(MANIFESTS))
        self.assertEqual(len(PROFILE_CATALOG.dispositions), 0)
        self.assertEqual(
            {item.runtime_product for item in tracks},
            {"docker-library/php", "docker-library/wordpress"},
        )
        self.assertEqual(
            {item.profile_id for item in PROFILE_CATALOG.profiles},
            {item.profile.id for item in MANIFESTS},
        )
        for release in PROFILE_CATALOG.values("php_release"):
            expected = tuple(sorted({
                item.architecture for item in tracks
                if item.php_release == release
            }))
            self.assertEqual(
                PROFILE_CATALOG.values("architecture", php_release=release),
                expected,
            )
        self.assertNotIn("planned", {item.value for item in QualificationStatus})

    def test_matching_tracks_and_values_cascade_without_nearest_fallback(self) -> None:
        expected_releases = tuple(sorted(
            {item.leaf.track.php_release for item in MANIFESTS},
            key=numeric_version_key,
        ))
        self.assertEqual(PROFILE_CATALOG.values("php_release"), expected_releases)
        self.assertEqual(
            PROFILE_CATALOG.values("runtime_product", php_release="8.3.35"),
            ("docker-library/php", "docker-library/wordpress"),
        )
        matches = PROFILE_CATALOG.matching_tracks(
            php_release="8.3.35",
            sapi=SAPI_ID,
            runtime_product="docker-library/php",
            architecture="arm64",
        )
        self.assertEqual(
            {item.ini_contract_id for item in matches},
            {"upstream-production", "no-main-ini"},
        )
        with self.assertRaisesRegex(ValueError, "unknown target-track field"):
            PROFILE_CATALOG.values("nearby_version")
        with self.assertRaisesRegex(ValueError, "unknown target-track filter"):
            PROFILE_CATALOG.matching_tracks(nearby_version="8.3")

    def test_release_values_are_sorted_numerically(self) -> None:
        leaves = tuple(
            leaf(track(release), release.replace(".", "-"))
            for release in ("8.10.2", "8.3.35", "8.9.11")
        )
        catalog = ProfileCatalog(leaves)
        self.assertEqual(
            catalog.values("php_release"),
            ("8.3.35", "8.9.11", "8.10.2"),
        )
        self.assertEqual(
            tuple(item.php_release for item in catalog.tracks),
            ("8.3.35", "8.9.11", "8.10.2"),
        )

    def test_unknown_combination_is_unavailable_not_planned(self) -> None:
        resolution = PROFILE_CATALOG.resolve(
            php_release="8.3.22",
            runtime_product="docker-library/wordpress",
            architecture="arm64",
            ini_contract_id="wordpress-default",
            sapi=SAPI_ID,
        )
        self.assertEqual(resolution.status, QualificationStatus.UNAVAILABLE)
        self.assertIsNone(resolution.track)
        self.assertIsNone(resolution.profile)

    def test_explicit_disposition_is_selectable_but_not_a_profile(self) -> None:
        rejected_track = track(
            product="docker-library/wordpress",
            architecture="arm64",
            ini="wordpress-default",
        )
        disposition = TrackDisposition(
            rejected_track,
            QualificationStatus.REJECTED,
            "calibration campaign failed",
            "campaign/test-001",
        )
        catalog = ProfileCatalog(dispositions=(disposition,))
        self.assertEqual(catalog.tracks, (rejected_track,))
        self.assertEqual(catalog.profiles, ())
        resolution = catalog.resolve(
            php_release="8.4.26",
            runtime_product="docker-library/wordpress",
            architecture="arm64",
            ini_contract_id="wordpress-default",
            sapi=SAPI_ID,
        )
        self.assertEqual(resolution.status, QualificationStatus.REJECTED)
        self.assertEqual(resolution.track, rejected_track)
        self.assertIsNone(resolution.profile)
        self.assertEqual(resolution.reason, "calibration campaign failed")

    def test_leaf_and_disposition_statuses_are_disjoint(self) -> None:
        with self.assertRaisesRegex(ValueError, "profile-leaf status"):
            leaf(
                track(),
                "unavailable",
                status=QualificationStatus.UNAVAILABLE,
            ).validate()
        with self.assertRaisesRegex(ValueError, "disposition status"):
            TrackDisposition(
                track(),
                QualificationStatus.RETIRED,
                "retired",
                "test",
            ).validate()

    def test_track_validation_is_strict(self) -> None:
        invalid = (
            replace(track(), php_release="8.x"),
            replace(track(), sapi="unknown-sapi"),
            replace(track(), default_workers=0),
            replace(track(), worker_default_source=None),
            replace(track(), architecture=" arm64"),
        )
        for item in invalid:
            with self.subTest(item=item):
                with self.assertRaises(ValueError):
                    ProfileCatalog((leaf(item, "invalid"),))

    def test_duplicate_profile_track_and_cross_kind_collision_are_rejected(self) -> None:
        exact = track()
        first = leaf(exact, "first")
        second = leaf(exact, "second")
        with self.assertRaisesRegex(ValueError, "duplicate profile for track"):
            ProfileCatalog((first, second))
        disposition = TrackDisposition(
            exact,
            QualificationStatus.UNAVAILABLE,
            "not shipped",
            "test",
        )
        with self.assertRaisesRegex(ValueError, "track collision"):
            ProfileCatalog((first,), (disposition,))

    def test_code_build_can_be_shared_without_aliasing_runtime_bundle(self) -> None:
        php_leaf = leaf(
            track(release="8.3.35"),
            "php",
            code_build="php-build/shared",
            runtime_bundle="bundle/docker-library-php",
        )
        wordpress_leaf = leaf(
            track(
                release="8.3.35",
                product="docker-library/wordpress",
                ini="wordpress-upstream-production",
            ),
            "wordpress",
            code_build="php-build/shared",
            runtime_bundle="bundle/docker-library-wordpress",
        )
        catalog = ProfileCatalog((php_leaf, wordpress_leaf))
        self.assertEqual(len(catalog.profiles), 2)
        self.assertEqual(php_leaf.php_code_build_id, wordpress_leaf.php_code_build_id)
        self.assertNotEqual(php_leaf.runtime_bundle_id, wordpress_leaf.runtime_bundle_id)
        self.assertNotEqual(php_leaf.profile_digest, wordpress_leaf.profile_digest)

    def test_frozen_plan_binds_profile_digest_and_target_workers(self) -> None:
        exact = leaf(track(ini="no-main-ini"), "exact")
        resolution = ProfileCatalog((exact,)).resolve(
            php_release="8.4.26",
            runtime_product="docker-library/php",
            architecture="amd64",
            ini_contract_id="no-main-ini",
            sapi=SAPI_ID,
        )
        plan = freeze_run_plan(
            resolution,
            RunDraft(
                "http://example.test:8080/index.php",
                None,
                "id",
                VerifierMode.HTTP,
                "/proof.txt",
                "fresh-nonce",
            ),
        )
        self.assertEqual(plan.profile_digest, exact.profile_digest)
        self.assertEqual(plan.workers.effective, 150)
        self.assertEqual(plan.workers.source, WorkerSource.PROFILE_DEFAULT)
        self.assertNotIn("--workers", plan.shell_command())
        self.assertIn("--verify-path /proof.txt", plan.shell_command())

        override = freeze_run_plan(
            resolution,
            RunDraft("http://example.test/index.php", 175, "id"),
        )
        self.assertEqual(override.workers.effective, 175)
        self.assertEqual(override.workers.source, WorkerSource.OVERRIDE)
        self.assertIn("--workers 175", override.shell_command())

    def test_pinned_candidate_planning_rejects_https(self) -> None:
        resolution = PROFILE_CATALOG.resolve(
            php_release="8.3.35",
            runtime_product="docker-library/php",
            architecture="amd64",
            ini_contract_id="upstream-production",
            sapi=SAPI_ID,
        )
        self.assertEqual(resolution.status, QualificationStatus.CANDIDATE)
        with self.assertRaisesRegex(PlanError, "requires direct HTTP"):
            freeze_run_plan(
                resolution,
                RunDraft("https://example.test/index.php", None, "id"),
                allow_candidate=True,
            )

    def test_frozen_plan_preserves_exact_command_text(self) -> None:
        resolution = PROFILE_CATALOG.resolve(
            php_release="8.3.35",
            runtime_product="docker-library/php",
            architecture="amd64",
            ini_contract_id="upstream-production",
            sapi=SAPI_ID,
        )
        plan = freeze_run_plan(
            resolution,
            RunDraft("http://example.test/index.php", None, "  printf x  "),
            allow_candidate=True,
        )
        self.assertEqual(plan.command, b"  printf x  ")
        self.assertEqual(plan.argv()[-1], "  printf x  ")

        whitespace = freeze_run_plan(
            resolution,
            RunDraft("http://example.test/index.php", None, " "),
            allow_candidate=True,
        )
        self.assertEqual(whitespace.command, b" ")

        with self.assertRaisesRegex(PlanError, "command is required"):
            freeze_run_plan(
                resolution,
                RunDraft("http://example.test/index.php", None, ""),
                allow_candidate=True,
            )

    def test_workerless_profile_omits_workers_and_rejects_override(self) -> None:
        cli_track = track(sapi="cli", workers=None, ini="no-main-ini")
        exact = leaf(cli_track, "cli")
        resolution = ProfileCatalog((exact,)).resolve(
            php_release="8.4.26",
            runtime_product="docker-library/php",
            architecture="amd64",
            ini_contract_id="no-main-ini",
            sapi="cli",
        )
        plan = freeze_run_plan(
            resolution,
            RunDraft("http://example.test/index.php", None, "id"),
        )
        self.assertIsNone(plan.workers.effective)
        self.assertEqual(plan.workers.source, WorkerSource.NOT_APPLICABLE)
        self.assertNotIn("--workers", plan.shell_command())
        with self.assertRaisesRegex(PlanError, "does not accept"):
            freeze_run_plan(
                resolution,
                RunDraft("http://example.test/index.php", 1, "id"),
            )

    def test_sapi_is_exact_and_never_falls_back_to_apache(self) -> None:
        resolution = PROFILE_CATALOG.resolve(
            php_release="8.4.26",
            runtime_product="docker-library/php",
            architecture="amd64",
            ini_contract_id="no-main-ini",
            sapi="cli",
        )
        self.assertEqual(resolution.status, QualificationStatus.UNAVAILABLE)
        self.assertIsNone(resolution.profile)


if __name__ == "__main__":
    unittest.main()
