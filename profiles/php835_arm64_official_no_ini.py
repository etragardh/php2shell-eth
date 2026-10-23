#!/usr/bin/env python3
"""PHP 8.3.35 official ARM64 Apache with no loaded php.ini.

This is the stock image's compiled/default configuration plus its two bundled
extension ini fragments.  It is intentionally separate from the
php.ini-production profile because those defaults change both A1 grooming and
the B1 stale-session/chunk layout.
"""

from dataclasses import replace

from .php835_arm64_official_production import PROFILE as PRODUCTION


PROFILE = replace(
    PRODUCTION,
    name="php-8.3.35-arm64-official-no-ini",
    environment=replace(
        PRODUCTION.environment,
        php_ini_sha256="none",
        ini_settings=(
            ("loaded_configuration_file", "(none)"),
            ("display_errors", "On"),
            ("memory_limit", "128M"),
            ("post_max_size", "8M"),
            ("max_input_vars", "1000"),
            ("max_input_nesting_level", "64"),
            ("max_execution_time", "30"),
            ("variables_order", "EGPCS"),
            ("session.save_handler", "files"),
            ("session.upload_progress.enabled", "On"),
            ("session.sid_length", "32"),
            ("session.sid_bits_per_character", "4"),
            ("session.use_strict_mode", "0"),
            ("output_buffering", "0"),
        ),
    ),
    heap=replace(
        PRODUCTION.heap,
        stale_session_id=0x8FD00,
        stale_session_reference=0x7A780,
        fake_array=0xF6398,
    ),
    a1=replace(
        PRODUCTION.a1,
        big=82,
        big_name=96,
        big_name_count=31,
        tail_big_count=0,
        burner_long_name_count=1,
        burner_long_name=400,
        late_groom_fields=14,
        late_groom_alt_value_count=5,
        late_groom_alt_value=32,
        released_fields=26,
        released_name=32,
        released_value=32,
        released_alt_value_count=3,
        released_alt_value=8,
        released_replacement_value=32,
        released_long_replacement_count=3,
        released_long_replacement_value=4000,
        query_params=31,
        query_value_length=96,
        query_secondary_released_fields=41,
        query_secondary_released_value_length=32,
        query_secondary_released_replacement_length=32,
        expected_status=200,
        expected_cookie=False,
    ),
    b1=replace(
        PRODUCTION.b1,
        fake_length=0x280000,
        sprays=28,
        page_spec=(
            256, 256, 256, 256, 256, 256, 256,
            256, 256, 256, 256, 256, 256, 256,
            256, 502,
            256, 256, 256, 256, 256, 256, 256,
            256, 256, 256, 256, 256,
        ),
        tail_pages=256,
        release_sprays=False,
        carrier_sprays=0,
        nested_fields=0,
        small_fields=0,
        expected_status=200,
    ),
    a2=replace(
        PRODUCTION.a2,
        expected_status=200,
    ),
)

