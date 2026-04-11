"""ApkSmith-shaped wrapper around the current SADroid instrumentation driver.

This file exists to freeze the public API along which the smali
rewriting engine will be split out into the standalone `ApkSmith`
package. It mirrors the dataclasses defined in ApkSmith's
``apksmith.config`` and ``apksmith.result`` so that callers can switch
between "SADroid internal" and "ApkSmith submodule" without changing
their call sites.

Nothing new happens here — the real work is still done by
``SADroid_bytecode_instrumentation.methodlog_instrumentation``. This is
just the boundary: once ApkSmith ships v0.1, SADroid's driver will
import the same shape from ``apksmith`` instead of this module and
delete everything below.

This file is deliberately the single entry point the rest of SADroid
should use going forward. New callers MUST go through ``instrument_apk``
rather than calling the legacy driver directly, so the migration to
the external ApkSmith package later is a one-line import change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from SADroid_bytecode_instrumentation import methodlog_instrumentation


# --- mirrored from apksmith.config -----------------------------------------

DEFAULT_SKIP_PACKAGES: tuple[str, ...] = (
    "android", "androidx", "kotlin", "kotlinx",
    "java", "javax", "dalvik", "junit", "org",
)
DEFAULT_SKIP_COM_CHILDREN: tuple[str, ...] = (
    "android", "facebook", "google", "adobe",
)

MethodCallback = Callable[[str, str], None]


@dataclass
class InstrumentConfig:
    """Knobs for one instrumentation run.

    Fields mirror ``apksmith.config.InstrumentConfig`` one-for-one so
    that migrating to the external package later is a pure import swap.
    """

    keystore: Path
    keystore_pass: str
    key_alias: str | None = None
    key_pass: str | None = None

    target_api_graph: dict[str, Any] = field(default_factory=dict)

    skip_package_prefixes: Iterable[str] = DEFAULT_SKIP_PACKAGES
    skip_com_children: Iterable[str] = DEFAULT_SKIP_COM_CHILDREN

    apktool: str | None = None
    zipalign: str | None = None
    apksigner: str | None = None

    log_tag: str = "SADroid"
    """logcat tag. SADroid keeps 'SADroid' for backward compatibility with
    its existing log analysis pipeline; external ApkSmith callers will
    default to 'ApkSmith' instead."""

    extra_local_regs: int = 2
    on_method: MethodCallback | None = None
    redecompile: bool = True

    def resolved_key_pass(self) -> str:
        return self.key_pass if self.key_pass is not None else self.keystore_pass


# --- mirrored from apksmith.result -----------------------------------------

@dataclass
class InstrumentStats:
    methods_scanned: int = 0
    methods_patched: int = 0
    methods_skipped_too_many_locals: int = 0
    branches_logged: int = 0
    labels_logged: int = 0
    target_api_hits: int = 0


@dataclass
class InstrumentResult:
    repacked_apk: Path
    app_hash: str
    methods: dict[str, str] = field(default_factory=dict)
    stats: InstrumentStats = field(default_factory=InstrumentStats)


# --- the public entry point ------------------------------------------------

def instrument_apk(
    apk_path: Path,
    output_dir: Path,  # noqa: ARG001 - kept for parity with ApkSmith; unused today
    config: InstrumentConfig,
    cursor,
) -> InstrumentResult:
    """Run the SADroid instrumentation pipeline with an ApkSmith-shaped API.

    The ``cursor`` positional argument is a temporary bridge: SADroid's
    current driver still wants a SQLite cursor for its ``app`` table
    INSERT. That coupling will be dropped once ApkSmith grows its own
    pipeline and SADroid delegates fully.
    """
    apk_path = Path(apk_path)
    if not apk_path.exists():
        raise FileNotFoundError(apk_path)

    methods: dict[str, str] = {}

    user_on_method = config.on_method

    def tee_on_method(method_hash: str, method_sign: str) -> None:
        # Capture into the InstrumentResult AND fan out to a caller-
        # supplied callback if one was provided.
        methods[method_hash] = method_sign
        if user_on_method is not None:
            user_on_method(method_hash, method_sign)

    repacked = methodlog_instrumentation(
        str(apk_path),
        config.redecompile,
        config.target_api_graph,
        cursor,
        keystore_path=str(config.keystore),
        keystore_pass=config.keystore_pass,
        key_alias=config.key_alias,
        key_pass=config.resolved_key_pass(),
        apktool_path=config.apktool,
        zipalign_path=config.zipalign,
        apksigner_path=config.apksigner,
        extra_on_method=tee_on_method,
    )

    # app_hash is derived from the APK filename stem; importing here to
    # avoid pulling SADroid_bytecode_instrumentation's side effects at
    # module import time.
    from smali_utils.core_SADroid_logger import hash_sign
    app_hash = hash_sign(apk_path.stem)

    return InstrumentResult(
        repacked_apk=Path(repacked),
        app_hash=app_hash,
        methods=methods,
    )


__all__ = [
    "InstrumentConfig",
    "InstrumentResult",
    "InstrumentStats",
    "instrument_apk",
]
