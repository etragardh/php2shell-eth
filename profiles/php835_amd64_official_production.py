#!/usr/bin/env python3
"""PHP 8.3.35 official AMD64 Apache with php.ini-production."""

from dataclasses import replace

from .php835_arm64_official_production import PROFILE as ARM64_PRODUCTION
from .types import SymbolOffsets


# The 64-bit Zend ABI and calibrated request-heap geometry are identical for
# the official AMD64 and ARM64 builds.  The ELF image, architecture metadata,
# and build-relative code-symbol offsets are architecture specific.
PROFILE = replace(
    ARM64_PRODUCTION,
    name="php-8.3.35-amd64-official",
    environment=replace(
        ARM64_PRODUCTION.environment,
        architecture="x86_64",
        image_id="sha256:90620e863c15e608cfebd058554d82d2c7fd816bdd690adc69027409cbb7a369",
        libphp_sha256="ea069762fa225a2d61ebf613db5686d7c29823acf641424d596f78fcaa1cdccb",
    ),
    symbols=SymbolOffsets(
        zval_ptr_dtor=0x49EC50,
        zif_system=0x3AC080,
    ),
)
