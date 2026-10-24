#!/usr/bin/env python3
"""Current official PHP 8.5.7 ARM64 Apache with no loaded php.ini.

Calibrated on Kali/aarch64 against the pinned official image digest.  The
image loads only its bundled sodium ini fragment; no main php.ini is loaded.
"""

from dataclasses import replace

from .php835_arm64_official_no_ini import PROFILE as PHP835_NOINI


PROFILE = replace(
    PHP835_NOINI,
    name="php-8.5.7-arm64-official-no-ini",
    environment=replace(
        PHP835_NOINI.environment,
        php_version="8.5.7",
        image=(
            "php:8.5.7-apache@sha256:"
            "098cbb56b025956f6aec60e35c4e4c8c8dc15359b6a215de4868a9aec2092dce"
        ),
        image_id=(
            "sha256:"
            "e220f33a0424c959ce19f2663d9bdcc3857b3a80e1eef4216cc1dd10bad787c7"
        ),
        libphp_sha256=(
            "c1d55f31423d01b7c093be31973650b0aafa475be9f67bfee3b430d4a2cab222"
        ),
        extension_configs=("docker-php-ext-sodium.ini",),
    ),
    allocator=replace(
        PHP835_NOINI.allocator,
        min_libphp_main_delta=-0x5000000,
        max_libphp_main_delta=-0x1000000,
        main_cluster_min_slots=1000,
        main_cluster_min_unique=1000,
        main_cluster_min_unique_ratio=0.50,
    ),
    symbols=replace(
        PHP835_NOINI.symbols,
        zval_ptr_dtor=0x75CC00,
        zif_system=0x52C030,
    ),
    heap=replace(
        PHP835_NOINI.heap,
        stale_session_id=0x71F00,
        stale_session_reference=0x79760,
        fake_array=0xF4398,
    ),
    a1=replace(
        PHP835_NOINI.a1,
        files=847,
        tail_big_count=6,
        released_long_replacement_count=17,
        expected_status=200,
        expected_cookie=False,
    ),
    b1=replace(
        PHP835_NOINI.b1,
        fake_length=0x180000,
        data_start=0x63000,
        page_spec=(
            256, 256, 256, 256, 256, 256, 256,
            256, 256, 502,
            256, 256, 256, 256, 256, 256, 256,
            256, 256, 256, 256, 256, 256, 256,
            256, 256, 256, 256,
        ),
        nested_fields=300,
        nested_depth=12,
    ),
)
