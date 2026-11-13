#!/usr/bin/env python3
#
# Generate CycloneDX SBOMs for the executables released from one
# build-scripts/linux.sh target:
#
#   <install>/sbom/tcp_tunnel_device.cdx.json
#   <install>/sbom/thermostat_device.cdx.json
#
# The SBOMs describe what is inside the shipped files, not everything the build
# uses: test only dependencies (boost, nlohmann-json, ...) and build tools are
# left out. Versions are taken from the build itself rather than from 3rdparty/,
# since the release presets build the dependencies with vcpkg:
#
#   * third party libraries: the vcpkg.spdx.json vcpkg writes for each port,
#     walked transitively from the ports the executables link.
#   * nabto-common: the git commit of the nabto-common submodule, as the overlay
#     port builds the local checkout and its port version is a placeholder.
#   * musl and the GCC runtime: the summary.csv in the bootlin toolchain.
#
# The executables are linked fully statically, so everything in their SBOMs,
# including the libc, is inside the binary. The nabto_device and nm_iam
# libraries are not distributed, so they get no SBOM of their own.
#
# Usage: generate_sbom.py <build_dir> <toolchain_root>
#
# Only the python standard library is used.

import csv
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid

SDK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# vcpkg ports linked by nabto_device and nm_iam (see the target_link_libraries
# in src/), and through them by the executables. Their own vcpkg dependencies
# are added transitively.
PORTS = ["mbedtls", "libevent", "tinycbor", "cjson"]

# The released executables: where they are built from, and what they link
# directly besides the SDK (see their target_link_libraries).
EXECUTABLES = {
    "tcp_tunnel_device": {
        "source": "apps/tcp_tunnel_device",
        "description": "Nabto Edge TCP tunnel device",
        "depends": {"nabto-common", "gopt", "cjson", "mbedtls"},
    },
    "thermostat_device": {
        "source": "examples/thermostat",
        "description": "Nabto Edge thermostat example device",
        "depends": {"nabto-common", "gopt", "cjson", "mbedtls", "tinycbor"},
    },
}

# Vendored sources which are compiled into the executables from 3rdparty/.
GOPT = {
    "type": "library",
    "bom-ref": "gopt",
    "name": "gopt",
    "version": "8.1",
    "description": "Command line argument parser, vendored in 3rdparty/gopt",
    "licenses": [{"license": {"name": "Public Domain"}}],
}


def die(msg):
    print("generate_sbom.py: " + msg, file=sys.stderr)
    sys.exit(1)


def read_cmake_cache(build_dir):
    cache = {}
    with open(os.path.join(build_dir, "CMakeCache.txt")) as f:
        for line in f:
            m = re.match(r"^([A-Za-z0-9_]+):[A-Z]+=(.*)$", line.rstrip("\n"))
            if m:
                cache[m.group(1)] = m.group(2)
    return cache


def git(*args):
    return subprocess.check_output(["git", "-C", SDK_DIR] + list(args), text=True).strip()


def sdk_version():
    # The version the build compiled into the library, see src/core/version.cmake.
    with open(os.path.join(SDK_DIR, "src", "core", "nc_version.c")) as f:
        m = re.search(r'nc_version_str = "([^"]*)"', f.read())
    if not m:
        die("could not read the version from src/core/nc_version.c")
    return m.group(1)


def file_hashes(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return [{"alg": "SHA-256", "content": h.hexdigest()}]


def license_entry(expr):
    if not expr or expr in ("NOASSERTION", "NONE"):
        return []
    return [{"expression": expr}]


def vcpkg_status(installed_dir):
    # Parse installed/vcpkg/status into {(port, triplet): {(port, triplet)}}.
    # Only fully installed packages are kept, and feature paragraphs are merged
    # into their port.
    path = os.path.join(installed_dir, "vcpkg", "status")
    deps = {}
    with open(path) as f:
        for para in f.read().split("\n\n"):
            fields = {}
            for line in para.splitlines():
                if ": " in line:
                    k, v = line.split(": ", 1)
                    fields[k] = v
            if "Package" not in fields or not fields.get("Status", "").endswith(" installed"):
                continue
            triplet = fields.get("Architecture")
            d = deps.setdefault((fields["Package"], triplet), set())
            for dep in fields.get("Depends", "").split(","):
                # "name:triplet", "name[feature]:triplet" or "name", the latter
                # meaning the triplet of the depending package.
                m = re.match(r"^([^\[:]+)(?:\[[^\]]*\])?(?::(.+))?$", dep.strip())
                if m:
                    d.add((m.group(1), m.group(2) or triplet))
    return deps


def vcpkg_closure(roots, status, triplet):
    # Ports linked into the target, i.e. installed for the target triplet. Host
    # tools (vcpkg-cmake, ...) are installed for the host triplet and drop out.
    seen = {}
    todo = list(roots)
    while todo:
        port = todo.pop()
        if port in seen:
            continue
        key = (port, triplet)
        if key not in status:
            continue
        target_deps = [name for name, t in status[key] if t == triplet]
        seen[port] = sorted(target_deps)
        todo.extend(target_deps)
    return seen


def vcpkg_component(installed_dir, triplet, port):
    path = os.path.join(installed_dir, triplet, "share", port, "vcpkg.spdx.json")
    with open(path) as f:
        spdx = json.load(f)
    pkgs = {p["SPDXID"]: p for p in spdx["packages"]}
    meta = pkgs["SPDXRef-port"]

    comp = {
        "type": "library",
        "bom-ref": port,
        "name": port,
        "version": meta["versionInfo"],
        # vcpkg records the license from the port manifest as concluded.
        "licenses": license_entry(meta.get("licenseConcluded")),
        "externalReferences": [],
        "properties": [{"name": "nabto:source", "value": "vcpkg"}],
    }
    if meta.get("homepage"):
        comp["externalReferences"].append({"type": "website", "url": meta["homepage"]})
    if meta.get("description"):
        comp["description"] = meta["description"]

    # The resources are the upstream sources the port downloaded. A github
    # source gives a precise purl, otherwise fall back to a generic one.
    purl = None
    for p in spdx["packages"]:
        if not p["SPDXID"].startswith("SPDXRef-resource"):
            continue
        loc = p.get("downloadLocation", "")
        comp["externalReferences"].append({
            "type": "distribution",
            "url": loc,
            "hashes": [{"alg": c["algorithm"].replace("SHA", "SHA-"), "content": c["checksumValue"]}
                       for c in p.get("checksums", [])],
        })
        m = re.match(r"git\+https://github\.com/([^/]+)/([^@]+)@(.+)$", loc)
        if m and purl is None:
            purl = "pkg:github/%s/%s@%s" % (m.group(1).lower(), m.group(2).lower(), m.group(3))
    comp["purl"] = purl or "pkg:generic/%s@%s" % (port, meta["versionInfo"])
    return comp


def nabto_common_component():
    sha = git("-C", "nabto-common", "rev-parse", "HEAD")
    return {
        "type": "library",
        "bom-ref": "nabto-common",
        "name": "nabto-common",
        "version": sha,
        "description": "Nabto common components: nn, coap, stun, streaming, mdns",
        "licenses": [{"expression": "Apache-2.0"}],
        "purl": "pkg:github/nabto/nabto-common@" + sha,
        "supplier": {"name": "Nabto"},
    }


def toolchain_components(toolchain_root):
    # summary.csv is the buildroot legal-info summary bootlin ships with each
    # toolchain. gcc-final occurs twice: the target runtime libraries (with the
    # runtime exception) and the host compiler. Only the former ends up in the
    # binary.
    rows = []
    with open(os.path.join(toolchain_root, "summary.csv")) as f:
        rows = list(csv.DictReader(f))
    musl = next((r for r in rows if r["PACKAGE"] == "musl"), None)
    gcc = next((r for r in rows if r["PACKAGE"] == "gcc-final" and "exception" in r["LICENSE"].lower()), None)
    if not musl or not gcc:
        die("could not find musl and gcc-final in " + toolchain_root + "/summary.csv")
    toolchain = os.path.basename(os.path.normpath(toolchain_root))
    return [
        {
            "type": "library",
            "bom-ref": "musl",
            "name": "musl",
            "version": musl["VERSION"],
            "description": "C standard library, statically linked",
            "licenses": [{"expression": "MIT"}],
            "purl": "pkg:generic/musl@%s?download_url=%s/%s" % (musl["VERSION"], musl["SOURCE SITE"], musl["SOURCE ARCHIVE"]),
            "properties": [{"name": "nabto:toolchain", "value": toolchain}],
        },
        {
            "type": "library",
            "bom-ref": "gcc-runtime",
            "name": "gcc-runtime",
            "version": gcc["VERSION"],
            "description": "GCC target runtime libraries (libgcc), statically linked",
            "licenses": [{"expression": "GPL-3.0-or-later WITH GCC-exception-3.1"}],
            "purl": "pkg:generic/gcc@%s?download_url=%s/%s" % (gcc["VERSION"], gcc["SOURCE SITE"], gcc["SOURCE ARCHIVE"]),
            "properties": [{"name": "nabto:toolchain", "value": toolchain}],
        },
    ]


def bom(root, components, dependencies):
    timestamp = datetime.datetime.now(datetime.timezone.utc)
    if "SOURCE_DATE_EPOCH" in os.environ:
        timestamp = datetime.datetime.fromtimestamp(int(os.environ["SOURCE_DATE_EPOCH"]), datetime.timezone.utc)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "build-scripts/generate_sbom.py"}]},
            "component": root,
        },
        "components": components,
        "dependencies": [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(dependencies.items())],
    }


def main():
    if len(sys.argv) != 3:
        die("usage: generate_sbom.py <build_dir> <toolchain_root>")
    build_dir, toolchain_root = sys.argv[1], sys.argv[2]

    cache = read_cmake_cache(build_dir)
    triplet = cache.get("VCPKG_TARGET_TRIPLET")
    installed_dir = cache.get("VCPKG_INSTALLED_DIR") or os.path.join(build_dir, "vcpkg_installed")
    install_dir = cache.get("CMAKE_INSTALL_PREFIX") or os.path.join(build_dir, "install")
    if not triplet:
        die("VCPKG_TARGET_TRIPLET is not set in " + build_dir + "/CMakeCache.txt, only vcpkg builds are supported")

    version = sdk_version()
    commit = git("rev-parse", "HEAD")
    status = vcpkg_status(installed_dir)

    ports = vcpkg_closure(PORTS, status, triplet)
    missing = [p for p in PORTS if p not in ports]
    if missing:
        die("ports %s are not installed for %s" % (missing, triplet))

    # nabto_device and nm_iam, which every executable links.
    sdk_ref = "nabto-embedded-sdk"
    sdk_component = {
        "type": "library",
        "bom-ref": sdk_ref,
        "name": "nabto-embedded-sdk",
        "version": version,
        "description": "Nabto Edge Embedded SDK: the nabto_device and nm_iam libraries",
        "supplier": {"name": "Nabto"},
        "licenses": [{"license": {"name": "Nabto commercial license, see LICENSING.md"}}],
        "purl": "pkg:github/nabto/nabto-embedded-sdk@" + commit,
    }
    components = ([sdk_component, nabto_common_component(), GOPT] +
                  toolchain_components(toolchain_root) +
                  [vcpkg_component(installed_dir, triplet, p) for p in sorted(ports)])
    deps = {sdk_ref: {"nabto-common", "mbedtls", "libevent", "tinycbor", "cjson"},
            "nabto-common": set(), "gopt": set(), "musl": set(), "gcc-runtime": set()}
    for p, d in ports.items():
        deps[p] = set(d)

    sbom_dir = os.path.join(install_dir, "sbom")
    os.makedirs(sbom_dir, exist_ok=True)

    for name, exe in EXECUTABLES.items():
        path = os.path.join(install_dir, "bin", name)
        if not os.path.exists(path):
            die("missing " + path)
        root = {
            "type": "application",
            "bom-ref": name,
            "name": name,
            "version": version,
            "description": exe["description"],
            "supplier": {"name": "Nabto"},
            "licenses": [{"license": {"name": "Nabto commercial license, see LICENSING.md"}}],
            "hashes": file_hashes(path),
            "purl": "pkg:github/nabto/nabto-embedded-sdk@%s#%s" % (commit, exe["source"]),
            "properties": [{"name": "nabto:vcpkg-triplet", "value": triplet}],
        }
        exe_deps = dict(deps)
        exe_deps[name] = exe["depends"] | {sdk_ref, "musl", "gcc-runtime"}
        with open(os.path.join(sbom_dir, name + ".cdx.json"), "w") as f:
            json.dump(bom(root, components, exe_deps), f, indent=2)
            f.write("\n")

    print("==> Wrote SBOMs to " + sbom_dir)


if __name__ == "__main__":
    main()
