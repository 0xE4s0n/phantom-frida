"""
Random name generator for stealth Frida builds.

Generates plausible-looking Android library/service names that blend in
with legitimate system components. Names avoid any association with
known tool names that might be blacklisted.
"""

import random
from datetime import datetime, timezone

# Word parts that look like legitimate Android/Linux library names
PREFIXES = [
    "lib",
    "sys",
    "dex",
    "art",
    "jit",
    "hwc",
    "gpu",
    "ndk",
    "arm",
    "elf",
    "ion",
    "ipc",
    "rpc",
    "hal",
    "app",
    "net",
    "ssl",
    "tls",
    "icu",
    "zst",
    "lz4",
    "bpf",
    "usb",
    "hid",
    "cam",
    "aud",
    "vid",
    "gfx",
    "vnd",
    "oem",
    "soc",
    "mtp",
]

MIDDLES = [
    "bridge",
    "helper",
    "core",
    "base",
    "native",
    "proxy",
    "service",
    "render",
    "codec",
    "engine",
    "parser",
    "binder",
    "loader",
    "mapper",
    "tracer",
    "linker",
    "daemon",
    "module",
    "stream",
    "buffer",
    "cache",
    "store",
    "alloc",
    "guard",
    "filter",
    "router",
    "socket",
    "tunnel",
    "thread",
    "signal",
]

SUFFIXES = [
    "rt",
    "ng",
    "ex",
    "v2",
    "io",
    "dl",
    "hq",
    "os",
    "vm",
    "xt",
    "fx",
    "ax",
    "mx",
    "px",
    "dx",
    "kr",
    "lm",
    "sv",
]

# Complete plausible names (look like real Android components)
PLAUSIBLE_NAMES = [
    "arthelper",
    "dexcache",
    "hwbridge",
    "nativeio",
    "jitcodec",
    "sysrender",
    "halproxy",
    "binderng",
    "netlayer",
    "armlinker",
    "ipcmodule",
    "gpualloc",
    "elfloader",
    "ionbuffer",
    "socengine",
    "rpcbridge",
    "oemcodec",
    "audiomix",
    "camstack",
    "gfxpipe",
    "threadmgr",
    "shmproxy",
    "signalhub",
    "pidmonit",
    "vmruntime",
    "libcutils",
    "libnative",
    "libbinder",
    "libhwcomp",
    "libsensor",
    "surfacemgr",
    "inputproc",
    "rendereng",
    "codecserv",
    "mediacore",
    "cryptohlp",
    "keymaster",
    "bootanim",
    "logdaemon",
    "ashmemgr",
    "voldproxy",
    "rildserv",
    "btservice",
    "wificore",
    "nfcstack",
    "grallochp",
    "eglstream",
    "vulkanldr",
    "skiaback",
    "harfbuzz",
]


def generate_name(seed: str | None = None) -> str:
    """
    Generate a random plausible name.

    Args:
        seed: Optional seed for reproducibility (e.g. date string for weekly builds)
    """
    if seed:
        rng = random.Random(seed)
    else:
        rng = random.Random()

    strategy = rng.randint(0, 2)

    if strategy == 0:
        # Pick from curated list
        return rng.choice(PLAUSIBLE_NAMES)
    elif strategy == 1:
        # Combine prefix + middle
        prefix = rng.choice(PREFIXES)
        middle = rng.choice(MIDDLES)
        return prefix + middle
    else:
        # Combine prefix + middle + suffix
        prefix = rng.choice(PREFIXES)
        middle = rng.choice(MIDDLES)
        suffix = rng.choice(SUFFIXES)
        return prefix + middle + suffix


def generate_port(seed: str | None = None) -> int:
    """
    Generate a random high port that looks like a legitimate service.

    Avoids:
    - Well-known ports (< 10000)
    - Common tool ports (27042, 5037, 8080, etc.)
    - Ports ending in round numbers
    """
    if seed:
        rng = random.Random(seed + "_port")
    else:
        rng = random.Random()

    blocked = {27042, 27043, 5037, 8080, 8443, 9090, 3000, 4000, 5000}
    while True:
        port = rng.randint(10000, 59999)
        if port not in blocked and port % 100 != 0 and port % 10 != 0:
            return port


def weekly_seed(now: datetime | None = None) -> str:
    """Return a stable UTC ISO year/week seed."""
    current = now or datetime.now(timezone.utc)
    iso_year, iso_week, _ = current.isocalendar()
    return f"{iso_year}-W{iso_week:02d}"


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate random build names")
    parser.add_argument("--seed", "-s", default=None, help="Seed for reproducibility")
    parser.add_argument(
        "--weekly", "-w", action="store_true", help="Use weekly seed (same name per week)"
    )
    parser.add_argument("--count", "-c", type=int, default=1, help="Number of names to generate")
    parser.add_argument("--port", "-p", action="store_true", help="Also generate a random port")
    parser.add_argument("--port-only", action="store_true", help="Output only the port number")
    parser.add_argument("--quiet", "-q", action="store_true", help="Output only the value (for CI)")
    args = parser.parse_args()

    seed = args.seed
    if args.weekly:
        seed = weekly_seed()
        if not args.quiet:
            print(f"Weekly seed: {seed}")

    for i in range(args.count):
        s = f"{seed}_{i}" if seed and args.count > 1 else seed
        if args.port_only:
            print(generate_port(s))
        elif args.port:
            name = generate_name(s)
            port = generate_port(s)
            if args.quiet:
                print(f"{name} {port}")
            else:
                print(f"{name} (port: {port})")
        else:
            print(generate_name(s))
