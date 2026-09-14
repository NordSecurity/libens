#!/usr/bin/python3
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = f"{SCRIPT_DIR.parent}"
RUST_VERSION = (SCRIPT_DIR.parent / "rust-toolchain").read_text().strip()

sys.path += [f"{PROJECT_ROOT}/3rd-party/rust_build_utils"]

import rust_build_utils.android_build_utils as abu
import rust_build_utils.darwin_build_utils as dbu
import rust_build_utils.rust_utils as rutils
from rust_build_utils.rust_utils_config import (
    NDK_IMAGE_PATH,
    NDK_VERSION,
    WINDOWS_CONTROL_FLOW_GUARD,
    WINDOWS_RUNTIME_LINKING,
    WindowsLinkingMethod,
)
import rust_build_utils.msvc as msvc

NDK_CLANG_DIR = (
    f"{NDK_IMAGE_PATH}/android-ndk-{NDK_VERSION}/toolchains/llvm/prebuilt/linux-x86_64/bin"
)

PROJECT_CONFIG = rutils.Project(
    rust_version=RUST_VERSION,
    root_dir=PROJECT_ROOT,
    working_dir=None,
)


def post_function_win(config, args):
    if config.target_os != "windows":
        return

    expect_static = args.linking == "static"

    for _, bins in LIBENS_CONFIG["windows"]["packages"].items():
        for _, binary in bins.items():
            if not binary.endswith(".dll"):
                continue

            dll_path = PROJECT_CONFIG.get_cargo_path(
                config.rust_target, binary, config.debug
            )
            if not os.path.isfile(dll_path):
                continue

            msvc_context = None
            if not msvc.is_msvc_active():
                msvc_context = msvc.activate_msvc(
                    "amd64" if config.arch == "x86_64" else config.arch
                )

            is_correct = msvc.check_for_static_runtime(Path(dll_path), expect_static)

            if msvc_context is not None:
                msvc.deactivate_msvc(msvc_context)

            if not is_correct:
                print(
                    f"Incorrect runtime linking for {dll_path}: expected static={expect_static}"
                )
                exit(1)

            print(f"Runtime linking for {dll_path} is correct (static={expect_static})")


LIBENS_CONFIG = {
    "linux": {
        "build_args": [],
        "archs": {
            "x86_64": {"env": {}},
            "aarch64": {"env": {}},
        },
        "packages": {
            "libens": {
                "ens": "libens.so",
            },
        },
    },
    "android": {
        "build_args": [],
        "archs": {
            "x86_64": {"env": {}},
            "aarch64": {"env": {}},
            "i686": {
                "env": {
                    "CC_i686-linux-android": (
                        [f"{NDK_CLANG_DIR}/i686-linux-android21-clang"],
                        "set",
                    )
                }
            },
            "armv7": {
                "env": {
                    "CC_armv7-linux-androideabi": (
                        [f"{NDK_CLANG_DIR}/armv7a-linux-androideabi21-clang"],
                        "set",
                    )
                }
            },
        },
        "packages": {
            "libens": {
                "ens": "libens.so",
            },
        },
    },
    "windows": {
        "build_args": [],
        "archs": {
            "x86_64": {"env": {}},
            "aarch64": {"env": {}},
        },
        "packages": {
            "libens": {
                "ens": "ens.dll",
                "ens.lib": "ens.dll.lib",
            },
        },
        "env": {"RUSTFLAGS": (f"{WINDOWS_CONTROL_FLOW_GUARD}", "set")},
        "post_build": [post_function_win],
    },
    "macos": {
        "build_args": [],
        "env": {},
        "packages": {"libens": {"ens": "libens.dylib"}},
    },
    "ios": {
        "build_args": [],
        "env": {},
        "packages": {"libens": {"ens": "libens.dylib"}},
    },
    "tvos": {
        "build_args": [],
        "env": {},
        "packages": {"libens": {"ens": "libens.dylib"}},
    },
    "tvos-sim": {
        "build_args": [],
        "env": {},
        "packages": {"libens": {"ens": "libens.dylib"}},
    },
    "ios-sim": {
        "build_args": [],
        "env": {},
        "packages": {"libens": {"ens": "libens.dylib"}},
    },
}


def main():
    parser = rutils.create_cli_parser()
    build_parser = parser._subparsers._group_actions[0].choices["build"]
    build_parser.add_argument(
        "--linking",
        choices=["static", "dynamic"],
        default="static",
        help="C runtime linking for Windows builds",
    )
    args = parser.parse_args()

    if args.command == "build":
        exec_build(args)
    elif args.command == "aar":
        abu.generate_aar(PROJECT_CONFIG, args)
    elif args.command == "lipo":
        exec_lipo(args)
    elif args.command == "xcframework":
        headers = {
            Path("libens/ensFFI.h"): Path(
                os.path.join(PROJECT_ROOT, "dist/apple/Sources/ensFFI.h")
            ),
        }
        dbu.create_xcframework(
            PROJECT_CONFIG,
            args.debug,
            "libensFFI",
            "ensFFI",
            headers,
            "libens.dylib",
        )
    else:
        assert False, f"command “{args.command}” not supported"


def exec_build(args):
    if args.os == "windows":
        method = (
            WindowsLinkingMethod.STATIC
            if args.linking == "static"
            else WindowsLinkingMethod.DYNAMIC
        )
        current = LIBENS_CONFIG["windows"]["env"]["RUSTFLAGS"][0]
        LIBENS_CONFIG["windows"]["env"]["RUSTFLAGS"] = (
            os.environ.get("RUSTFLAGS", "") + current + WINDOWS_RUNTIME_LINKING[method],
            "set",
        )

    config = rutils.CargoConfig(
        args.os,
        args.arch,
        args.debug,
    )
    rutils.check_config(config)
    call_build(config, args)


def call_build(config, args):
    print(f"Building {config.target_os} {config.arch} {config.debug}")
    rutils.config_local_env_vars(config, LIBENS_CONFIG)

    packages = LIBENS_CONFIG[config.target_os]["packages"]

    rutils.cargo_build(
        PROJECT_CONFIG,
        config,
        packages,
        LIBENS_CONFIG[config.target_os].get("build_args", None),
    )

    for post in LIBENS_CONFIG[config.target_os].get("post_build", []):
        post(config, args)


def exec_lipo(args):
    for target_os in rutils.LIPO_TARGET_OSES:
        if target_os in LIBENS_CONFIG:
            dbu.lipo(
                PROJECT_CONFIG,
                args.debug,
                target_os,
                LIBENS_CONFIG[target_os]["packages"],
            )


if __name__ == "__main__":
    main()
