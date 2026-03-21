#!/usr/bin/env python3
"""
Pack host directories into .data files with a preload manifest for js-kernel.js.

Usage:
    python3 pack-preload.py <host_dir>@<mount_point> [-o <output_dir>]

Example:
    python3 pack-preload.py /root/cpython/Lib@/lib/python3.15 -o ./out

Generates:
    <output_dir>/<name>.data            - concatenated binary blob
    <output_dir>/preload-manifest.json  - metadata for js-kernel.js loadPackage
"""

import argparse
import json
import os
import sys


def parse_mount_spec(spec):
    """Parse 'host_dir@mount_point' into (host_dir, mount_point)."""
    if "@" not in spec:
        print(f"Error: mount spec must be 'host_dir@mount_point', got: {spec}", file=sys.stderr)
        sys.exit(1)
    host_dir, mount_point = spec.rsplit("@", 1)
    if not os.path.isdir(host_dir):
        print(f"Error: host directory not found: {host_dir}", file=sys.stderr)
        sys.exit(1)
    if not mount_point.startswith("/"):
        print(f"Error: mount point must be absolute path: {mount_point}", file=sys.stderr)
        sys.exit(1)
    return host_dir, mount_point


def collect_files(host_dir, mount_point):
    """Walk host_dir and collect (host_path, mount_path) pairs for regular files."""
    result = []
    for dirpath, dirnames, filenames in os.walk(host_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in filenames:
            if fname.startswith("."):
                continue
            host_path = os.path.join(dirpath, fname)
            if not os.path.isfile(host_path):
                continue
            rel = os.path.relpath(host_path, host_dir)
            mount_path = mount_point.rstrip("/") + "/" + rel
            result.append((host_path, mount_path))
    result.sort(key=lambda x: x[1])
    return result


def collect_directories(host_dir, mount_point):
    """Walk host_dir and collect all directories (including empty ones)."""
    dirs = set()
    dirs.add(mount_point.rstrip("/") or "/")
    for dirpath, dirnames, filenames in os.walk(host_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        rel = os.path.relpath(dirpath, host_dir)
        if rel == ".":
            continue
        mount_dir = mount_point.rstrip("/") + "/" + rel
        dirs.add(mount_dir)
    all_dirs = set()
    for d in dirs:
        while d and d != "/":
            all_dirs.add(d)
            d = os.path.dirname(d)
    return sorted(all_dirs)


def pack_data(file_pairs, output_path):
    """Concatenate all files into a single .data blob, return file metadata."""
    files_meta = []
    offset = 0
    with open(output_path, "wb") as out:
        for host_path, mount_path in file_pairs:
            size = os.path.getsize(host_path)
            with open(host_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
            files_meta.append({
                "filename": mount_path,
                "start": offset,
                "end": offset + size,
            })
            offset += size
    return files_meta, offset


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mount_specs", nargs="+",
                        help="Mount specs: host_dir@mount_point")
    parser.add_argument("-o", "--output-dir", required=True,
                        help="Output directory for .data and manifest")
    args = parser.parse_args()

    output_dir = args.output_dir
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    manifest = []

    for spec in args.mount_specs:
        host_dir, mount_point = parse_mount_spec(spec)
        file_pairs = collect_files(host_dir, mount_point)
        directories = collect_directories(host_dir, mount_point)

        if not file_pairs and not directories:
            print(f"Warning: no files found in {host_dir}", file=sys.stderr)
            continue

        data_name = mount_point.strip("/").replace("/", "_") + ".data"
        data_path = os.path.join(output_dir, data_name)

        files_meta, total_size = pack_data(file_pairs, data_path)

        entry = {
            "packageDataName": data_name,
            "remote_package_size": total_size,
            "directories": directories,
            "files": files_meta,
        }
        manifest.append(entry)

        print(f"Packed {len(file_pairs)} files, {len(directories)} dirs ({total_size} bytes) -> {data_name}")

    manifest_path = os.path.join(output_dir, "preload-manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f)

    print(f"Manifest written to {manifest_path}")


if __name__ == "__main__":
    main()
