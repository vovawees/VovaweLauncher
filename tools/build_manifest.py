#!/usr/bin/env python3
"""Сканирует data/client_files/ и собирает data/manifest.json для лаунчера и Nginx."""
import argparse
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def detect_tags(rel_posix: str) -> tuple[str, str | None, bool]:
    # os: all | linux | win32
    os_tag = "all"
    if "/linux/" in rel_posix or rel_posix.startswith("natives/linux/"):
        os_tag = "linux"
    elif "/win32/" in rel_posix or rel_posix.startswith("natives/win32/"):
        os_tag = "win32"

    # Опциональные модули (привязываются к тумблерам в настройках лаунчера)
    optional_group = None
    if rel_posix.startswith("shaderpacks/"):
        optional_group = "shaders"

    # Удалять ли лишние файлы в этой папке, если их нет в манифесте
    strict_dir = rel_posix.startswith("mods/")
    return os_tag, optional_group, strict_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Dead Mile '96 client manifest.json")
    parser.add_argument("--source", type=Path, default=Path("data/client_files"))
    parser.add_argument("--output", type=Path, default=Path("data/manifest.json"))
    parser.add_argument("--client-version", default="0.9.6")
    parser.add_argument("--mc-version", default="1.20.1")
    parser.add_argument("--forge-version", default="47.3.0")
    args = parser.parse_args()

    args.source.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    files = []
    for file_path in sorted(args.source.rglob("*")):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(args.source).as_posix()
        os_tag, opt_group, strict_dir = detect_tags(rel)
        files.append({
            "path": rel,
            "size": file_path.stat().st_size,
            "sha256": sha256_file(file_path),
            "os": os_tag,
            "optional": opt_group,
            "strict": strict_dir,
        })

    manifest = {
        "client_version": args.client_version,
        "mc_version": args.mc_version,
        "forge_version": args.forge_version,
        "strict_dirs": ["mods"],
        "files_count": len(files),
        "files": files,
    }
    args.output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Manifest saved to {args.output} ({len(files)} files)")


if __name__ == "__main__":
    main()
