"""Scan tracked and nonignored new files without credential verification.

All tests and fixtures are scanned. Prefer named synthetic identifiers; an
unavoidable scanner false positive requires a reviewed, same-line
``pragma: allowlist secret`` with a reason. No baseline hides existing findings.
Only paths, line numbers and finding types are printed, never matched values.
"""

import logging
import re
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = re.compile(r"(?<![A-Za-z0-9])\d{12}(?![A-Za-z0-9])")
_ARCHIVE_LIMIT = 10 * 1024 * 1024
_CONTENT_LIMIT = 100 * 1024 * 1024


class _IncompleteScan(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno >= logging.WARNING:
            raise ValueError("scanner reported incomplete evidence")


def _scan_content(path: Path) -> bytes:
    compressed = path.name.endswith(".gz")
    limit = _ARCHIVE_LIMIT if compressed else _CONTENT_LIMIT
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("scan input exceeds bounded size")
    if not compressed:
        data.decode("utf-8")  # Unsupported binary input is incomplete scan evidence.
        return data
    decoder = zlib.decompressobj(wbits=31)
    result = bytearray()
    for start in range(0, len(data), 16_384):
        result.extend(
            decoder.decompress(data[start : start + 16_384], _CONTENT_LIMIT - len(result) + 1)
        )
        if len(result) > _CONTENT_LIMIT or decoder.unconsumed_tail or decoder.unused_data:
            raise ValueError("invalid or oversized compressed scan input")
    if not decoder.eof:
        raise ValueError("incomplete compressed scan input")
    result.decode("utf-8")
    return bytes(result)


def main() -> int:
    try:
        from detect_secrets.core.scan import scan_file
        from detect_secrets.settings import default_settings

        if sys.argv[1:]:
            paths = [Path(name).resolve(strict=True) for name in sys.argv[1:]]
        else:
            listed = subprocess.run(
                ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                cwd=ROOT,
                capture_output=True,
                check=True,
            )
            paths = [ROOT / name.decode("utf-8") for name in listed.stdout.split(b"\0") if name]
        paths = sorted(set(paths))
        if not paths or any(not path.is_file() or path.is_symlink() for path in paths):
            raise ValueError("missing or unsupported scan input")
        found = False
        # Scan bounded text copies, including expanded gzip content. A sibling JSON file
        # is not proof that an archive was scanned. Copies share one root on Windows too.
        with tempfile.TemporaryDirectory(prefix="cloudsecops-secret-scan-") as directory:
            scan_root = Path(directory)
            originals: dict[str, Path] = {}
            copies: list[Path] = []
            for index, path in enumerate(paths):
                data = _scan_content(path)
                for line_number, line in enumerate(data.decode("utf-8").splitlines(), 1):
                    if ACCOUNT.search(line):
                        print(f"{path}:{line_number}: account-shaped identifier")
                        found = True
                suffix = ".json" if path.name.endswith(".gz") else path.suffix
                copy = scan_root / f"input-{index}{suffix}"
                copy.write_bytes(data)
                originals[copy.name] = path
                copies.append(copy)
            # CLI discovery slices real paths by cwd spelling and can silently skip
            # Windows aliases. Scan each prepared absolute file directly. These
            # default local filters do not enable remote credential verification.
            logger = logging.getLogger("detect-secrets")
            handler = _IncompleteScan(level=logging.WARNING)
            previous_level = logger.level
            logger.setLevel(logging.WARNING)
            logger.addHandler(handler)
            try:
                with default_settings() as settings:
                    if not settings.json().get("plugins_used"):
                        raise ValueError("missing scanner plugins")
                    for copy in copies:
                        for finding in scan_file(str(copy.resolve(strict=True))):
                            original = originals[copy.name]
                            print(f"{original}:{finding.line_number}: {finding.type}")
                            found = True
            finally:
                logger.removeHandler(handler)
                logger.setLevel(previous_level)
        print(f"scanned {len(paths)} file(s); {'findings present' if found else 'no findings'}")
        return int(found)
    except (
        ImportError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        zlib.error,
        subprocess.CalledProcessError,
    ):
        print("Secret scan failed: required scan evidence unavailable.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    # Third-party file reads use the process locale and otherwise silently skip
    # valid UTF-8 on Windows. Re-exec only this local scanner with explicit UTF-8.
    if not sys.flags.utf8_mode:
        raise SystemExit(
            subprocess.call(
                [sys.executable, "-X", "utf8", str(Path(__file__).resolve()), *sys.argv[1:]]
            )
        )
    raise SystemExit(main())
