#!/usr/bin/env python3

import argparse
import datetime
import getpass
import json
import os
import platform
import re
import hashlib
import tempfile
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Optional

from tools import safe_logd

ROOT = Path(__file__).resolve().parent
DIAGNOSTIC_DIR = ROOT / "diagnostic"
DIAGNOSTIC_CHUNK_SIZE = 40 * 1024 * 1024
DIAGNOSTIC_BLOCKER_MESSAGE = "Safe diagnostic generation failed; inspect the metadata error."


def current_source_commit() -> str:
    """Read the actual source revision; never invent a zero commit on failure."""
    result = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=str(ROOT),
                            capture_output=True, text=True, timeout=5)
    commit = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", commit):
        raise ValueError("Cannot identify the source Git commit")
    return commit


def current_source_tree() -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=str(ROOT),
                            capture_output=True, text=True, timeout=5)
    tree = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", tree):
        raise ValueError("Cannot identify the source Git tree")
    return tree


def current_commit_id() -> str:
    return current_source_commit()[:8]


def require_clean_source() -> None:
    result = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=str(ROOT),
                            capture_output=True, text=True, timeout=10)
    if result.returncode != 0 or result.stdout.strip():
        raise ValueError("Commit source changes and resolve untracked files before generating diagnostics")


def validate_diagnostic_directory() -> None:
    expected = ROOT.resolve() / "diagnostic"
    if DIAGNOSTIC_DIR.is_symlink() or DIAGNOSTIC_DIR.resolve() != expected:
        raise ValueError("diagnostic directory must not be a symlink or escape the repository")


def diagnostic_paths_for_commit(commit_id: Optional[str] = None) -> tuple[Path, Path, str]:
    """Use only the real repository's diagnostic directory; refuse redirection."""
    validate_diagnostic_directory()
    DIAGNOSTIC_DIR.mkdir(exist_ok=True)
    commit_id = commit_id or current_commit_id()
    if not re.fullmatch(r"[0-9a-f]{8}", commit_id):
        raise ValueError("Invalid source commit identifier")
    return (DIAGNOSTIC_DIR / f"build-{commit_id}.logd",
            DIAGNOSTIC_DIR / f"build-{commit_id}.json", commit_id)


def split_diagnostic_logd(logd_path: Path, chunk_size: int = DIAGNOSTIC_CHUNK_SIZE) -> list[Path]:
    """Split an oversized .logd into numbered .logd chunks and remove the original."""
    if not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("Diagnostic chunk size must be positive")
    if logd_path.stat().st_size <= chunk_size:
        return [logd_path]

    chunks: list[Path] = []
    stem = logd_path.stem
    with logd_path.open("rb") as source:
        index = 1
        while True:
            data = source.read(chunk_size)
            if not data:
                break
            chunk_path = logd_path.with_name(f"{stem}-part{index:03d}.logd")
            with chunk_path.open("xb") as chunk:
                chunk.write(data)
            chunks.append(chunk_path)
            index += 1

    logd_path.unlink()
    return chunks


@dataclass
class Module:
    name: str
    language: str
    dir: Path
    build_cmd: list[str]
    clean_cmd: list[str]
    build_dir: Optional[Path] = None
    env: Optional[dict[str, str]] = None

MODULES = [
    Module(
        name="backend",
        language="Rust",
        dir=ROOT / "backend",
        build_cmd=["cargo", "build"],
        clean_cmd=["cargo", "clean"],
        build_dir=ROOT / "backend" / "target",
        env={"CARGO_TERM_COLOR": "always"},
    ),
    Module(
        name="frontend",
        language="TypeScript",
        dir=ROOT / "frontend",
        build_cmd=["npm", "run", "build"],
        clean_cmd=["rm", "-rf", "node_modules", "dist"],
        build_dir=ROOT / "frontend" / "dist",
        env={"NODE_ENV": "production"},
    ),
    Module(
        name="market",
        language="Go",
        dir=ROOT / "market",
        build_cmd=["go", "build", "-o", "market", "."],
        clean_cmd=["rm", "-f", "market"],
        build_dir=ROOT / "market" / "market",
    ),
    Module(
        name="frailbox",
        language="C",
        dir=ROOT / "frailbox",
        build_cmd=["make"],
        clean_cmd=["make", "distclean"],
        build_dir=ROOT / "frailbox" / "frailbox",
    ),
    Module(
        name="engine",
        language="C++",
        dir=ROOT / "frailbox" / "engine",
        build_cmd=["cmake", "--build", "build"],
        clean_cmd=["rm", "-rf", "build"],
        build_dir=ROOT / "frailbox" / "engine" / "build" / "trial-engine",
    ),
    Module(
        name="compliance",
        language="Java",
        dir=ROOT / "compliance",
        build_cmd=["javac", "-d", "build", "ComplianceAuditor.java"],
        clean_cmd=["rm", "-rf", "build"],
        build_dir=ROOT / "compliance" / "build",
    ),
    Module(
        name="v2-market-stream",
        language="Ruby",
        dir=ROOT / "v2" / "services",
        build_cmd=["ruby", "-c", "market_stream.rb"],
        clean_cmd=["echo", "Ruby has no build artifacts to clean"],
        build_dir=None,
    ),
    Module(
        name="nfc-scanner",
        language="Lua",
        dir=ROOT / "frailbox" / "nfc",
        build_cmd=["luac", "-p", "scanner.lua"],
        clean_cmd=["echo", "Lua has no build artifacts to clean"],
        build_dir=None,
    ),
    Module(
        name="openapi-haskell",
        language="Haskell",
        dir=ROOT / "docs" / "openapi",
        build_cmd=["ghc", "-fno-code", "Types.hs", "Server.hs", "Validate.hs", "Generate.hs"],
        clean_cmd=["rm", "-f", "*.hi", "*.o", "*.hie"],
        build_dir=None,
    ),
    Module(
        name="openapi-tools",
        language="Lua",
        dir=ROOT / "tools",
        build_cmd=["luac", "-p", "openapi_diff.lua", "openapi_mock.lua", "openapi_pact.lua"],
        clean_cmd=["echo", "Nothing to clean"],
        build_dir=None,
    ),
]

class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    GRAY = "\033[90m"

def color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{Colors.RESET}"

def check_prerequisites() -> list[str]:
    required = {
        "cargo": "Rust",
        "npm": "Node.js",
        "go": "Go",
        "gcc": "C (GCC)",
        "g++": "C++ (GCC)",
        "cmake": "CMake",
        "make": "Make",
        "python3": "Python",
        "javac": "Java (JDK)",
        "ruby": "Ruby",
        "luac": "Lua",
        "ghc": "GHC (Haskell)",
    }

    missing = []
    for cmd, label in required.items():
        if shutil.which(cmd) is None:
            missing.append(f"{label} ({cmd})")

    return missing

def build_module(
    module: Module,
    release: bool = False,
    verbose: bool = False,
) -> tuple[bool, float, str]:

    print(f"\n  {color('▸', Colors.CYAN)} Building {color(module.name, Colors.BOLD)} ({module.language})...")

    env = os.environ.copy()
    if module.env:
        env.update(module.env)

    start = time.time()

    if module.name == "frontend":
        node_modules = module.dir / "node_modules"
        if not node_modules.exists():
            print(f"       {color('npm install...', Colors.GRAY)}")
            try:
                install_result = subprocess.run(
                    ["npm", "install"],
                    cwd=str(module.dir),
                    capture_output=not verbose,
                    text=True,
                    timeout=120,
                    env={k: v for k, v in env.items() if k != "NODE_ENV"},
                )
                if install_result.returncode != 0:
                    return False, time.time() - start, f"npm install failed:\n{install_result.stderr}"
            except subprocess.TimeoutExpired:
                return False, time.time() - start, "npm install TIMEOUT (120s)"

    if module.name == "engine":

        build_type = "Release" if release else "Debug"
        try:
            cfg_result = subprocess.run(
                ["cmake", "-S", ".", "-B", "build",
                 f"-DCMAKE_BUILD_TYPE={build_type}"],
                cwd=str(module.dir),
                capture_output=True,
                text=True,
                timeout=120,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return False, time.time() - start, "CMake configure TIMEOUT (120s)"
        except FileNotFoundError as e:
            return False, 0, f"Command not found: {e}"
        if cfg_result.returncode != 0:
            output_lines = []
            if cfg_result.stdout:
                output_lines.append(cfg_result.stdout.strip())
            if cfg_result.stderr:
                output_lines.append(cfg_result.stderr.strip())
            output = "\n".join(output_lines)
            return False, time.time() - start, (
                f"CMake configure failed:\n{output}")
        if verbose:
            print(f"       {color('cmake configured', Colors.GRAY)}")
        cmd = ["cmake", "--build", "build"]
        if release:
            cmd.append("--config")
            cmd.append("Release")
    else:
        cmd = list(module.build_cmd)
        if release and module.name == "backend":
            cmd.append("--release")

    try:
        result = subprocess.run(
            cmd,
            cwd=str(module.dir),
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return False, time.time() - start, "BUILD TIMEOUT (300s)"
    except FileNotFoundError as e:
        return False, 0, f"Command not found: {e}"

    elapsed = time.time() - start
    output_lines = []

    if result.stdout:
        output_lines.append(result.stdout.strip())
    if result.stderr:
        output_lines.append(result.stderr.strip())

    output = "\n".join(output_lines)
    success = result.returncode == 0

    return success, elapsed, output

def clean_module(module: Module, verbose: bool = False) -> bool:
    print(f"  {color('▸', Colors.YELLOW)} Cleaning {module.name}...")
    try:
        subprocess.run(
            module.clean_cmd,
            cwd=str(module.dir),
            capture_output=not verbose,
            text=True,
            timeout=60,
            env=os.environ.copy(),
        )
        return True
    except Exception as e:
        print(f"    {color('✗', Colors.RED)} Clean failed: {e}")
        return False

def verify_binary(module: Module) -> Optional[str]:
    if module.build_dir is None:
        return None
    path = module.build_dir
    if module.name == "backend":

        target = path / "debug" / module.name
        if not target.exists():
            target = path / "release" / module.name
        if target.exists():
            return str(target)
    if path.exists():
        return str(path)
    return None

def run_cmd(cmd: list[str], **kwargs) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False, **kwargs
        )
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        return result.returncode == 0, output.strip()
    except Exception as e:
        return False, str(e)


def redact_diagnostic_text(value: str) -> str:
    """Remove known local identities/paths; this is not a universal secret filter."""
    paths = [ROOT, Path.home(), Path(tempfile.gettempdir())]
    for name in ("TMP", "TEMP", "TMPDIR"):
        if os.environ.get(name):
            paths.append(Path(os.environ[name]))
    tokens = set()
    for path in paths:
        for spelling in (str(path), str(path.resolve())):
            if spelling and spelling not in {"/", "\\"}:
                tokens.update((spelling, spelling.replace("\\", "/"), spelling.replace("/", "\\")))
    redacted = value
    for token in sorted(tokens, key=len, reverse=True):
        redacted = re.sub(re.escape(token), "<redacted-path>", redacted, flags=re.IGNORECASE)
    identities = {getpass.getuser(), platform.node()}
    identities.update(os.environ.get(name, "") for name in ("USER", "USERNAME", "LOGNAME"))
    for token in sorted(filter(None, identities), key=len, reverse=True):
        redacted = re.sub(r"(?<![\w.-])" + re.escape(token) + r"(?![\w.-])",
                          "<redacted-identity>", redacted, flags=re.IGNORECASE)
    # Known credential labels only; arbitrary secrets still require review.
    redacted = re.sub(r"(?i)(\b(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*)[^\s,;]+",
                      r"\1<redacted-secret>", redacted)
    redacted = re.sub(r"(?i)(\bAuthorization\s*:\s*Bearer\s+)\S+", r"\1<redacted-secret>", redacted)
    return redacted


def repo_relative_metadata_path(path: Optional[str]) -> Optional[str]:
    if path is None:
        return None
    try:
        if PureWindowsPath(path).drive and not Path(path).is_absolute():
            return None
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = ROOT / candidate
        return candidate.resolve().relative_to(ROOT.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def collect_system_info() -> str:
    """An explicit minimal snapshot: no HOME/files/env/mount-table discovery."""
    return redact_diagnostic_text("\n".join([
        "Tent of Trials - Minimal Build Environment",
        f"python: {sys.version.split()[0]}",
        f"platform: {platform.system()}",
        f"machine: {platform.machine()}",
        f"cpu_count: {os.cpu_count()}",
        "",
    ]))


def diagnostic_output_preview(output: str, full_available: bool) -> dict:
    clean = redact_diagnostic_text(output).encode("utf-8")
    limit = 16 * 1024
    return {"output": clean[:limit].decode("utf-8", errors="ignore"),
            "output_truncated": len(clean) > limit,
            "output_byte_count": len(clean),
            "full_output": "build.log" if full_available else None}


def build_diagnostic_report(
    results: list[tuple[str, bool, float, str, Optional[str]]],
    commit_id: str,
    logd_relpaths: Optional[list[str]] = None,
    password: Optional[str] = None,
    logd_error: Optional[str] = None,
    chunked: bool = False,
    message_blocker: Optional[str] = None,
    source_commit: Optional[str] = None,
    source_tree: Optional[str] = None,
) -> dict:
    diagnostic_logd: Optional[str | list[str]]
    if not logd_relpaths:
        diagnostic_logd = None
    elif len(logd_relpaths) == 1:
        diagnostic_logd = logd_relpaths[0]
    else:
        diagnostic_logd = logd_relpaths

    decrypt_target = logd_relpaths[0] if logd_relpaths and len(logd_relpaths) == 1 else None
    if logd_relpaths and len(logd_relpaths) > 1:
        decrypt_target = str((DIAGNOSTIC_DIR / f"build-{commit_id}.logd").relative_to(ROOT))

    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "commit": commit_id,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "source_dirty": False,
        "format": safe_logd.FORMAT,
        "password_semantics": "Random base64url AES-256 key. Publishing this JSON permits decryption and forgery; not an author signature.",
        "diagnostic_logd": diagnostic_logd,
        "diagnostic_logd_error": redact_diagnostic_text(logd_error) if logd_error else None,
        "message_blocker": redact_diagnostic_text(message_blocker) if message_blocker else None,
        "chunked": chunked,
        "chunk_size_bytes": DIAGNOSTIC_CHUNK_SIZE if chunked else None,
        "password": password,
        "decrypt_command": (
            f"python3 tools/safe_logd.py unpack {decrypt_target} <new-output-dir> --metadata diagnostic/build-{commit_id}.json"
            if decrypt_target and password else None
        ),
        "total_modules": len(results),
        "passed": sum(1 for _, s, _, _, _ in results if s),
        "failed": sum(1 for _, s, _, _, _ in results if not s),
        "modules": [
            {
                "name": name,
                "status": "PASS" if success else "FAIL",
                "elapsed_seconds": round(elapsed, 3),
                "artifact": repo_relative_metadata_path(binary),
                **diagnostic_output_preview(output, bool(logd_relpaths)),
            }
            for name, success, elapsed, output, binary in results
        ],
        "pr_note": (
            (f"Include the encrypted diagnostic logd artifact(s): {', '.join(logd_relpaths)}. " if logd_relpaths else "Encrypted diagnostic logd artifact was not created; include this JSON report showing why. ")
            + "The encrypted .logd is the required diagnostic content for PR review; this JSON file is metadata. "
            + "Maintainers may ask you to remove these diagnostic artifacts before merging."
        ),
    }
    return report


def write_diagnostic_report(metadata_path: Path, report: dict) -> None:
    with metadata_path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(report, indent=2) + "\n")
    print(f"    {color('✓', Colors.GREEN)} {metadata_path.relative_to(ROOT)} created")


def commit_diagnostic_artifacts(paths: list[Path], commit_id: str) -> bool:
    """Commit diagnostic files as soon as they are produced."""
    existing = [path for path in paths if path.exists()]
    if not existing:
        print(f"    {color('✗', Colors.RED)} No diagnostic artifacts found to commit")
        return False

    relpaths = [str(path.relative_to(ROOT)) for path in existing]
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", *relpaths],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if status.returncode != 0:
        print(f"    {color('✗', Colors.RED)} Could not inspect diagnostic git status: {status.stderr.strip()}")
        return False
    if not status.stdout.strip():
        print(f"    {color('✓', Colors.GREEN)} Diagnostic artifacts already committed")
        return True

    add = subprocess.run(
        ["git", "add", "--", *relpaths],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if add.returncode != 0:
        print(f"    {color('✗', Colors.RED)} Could not stage diagnostic artifacts: {add.stderr.strip()}")
        return False

    commit = subprocess.run(
        ["git", "commit", "-m", f"Add build diagnostics for {commit_id}", "--", *relpaths],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    if commit.returncode != 0:
        output = commit.stderr.strip() or commit.stdout.strip()
        print(f"    {color('✗', Colors.RED)} Could not commit diagnostic artifacts: {output}")
        return False

    print(f"    {color('✓', Colors.GREEN)} Diagnostic artifacts committed")
    return True


def generate_logd(
    results: list[tuple[str, bool, float, str, Optional[str]]],
    verbose: bool = False,
    source_commit: Optional[str] = None,
    source_tree: Optional[str] = None,
) -> bool:
    """Create real encrypted diagnostics from three explicit, redacted texts."""
    metadata_path = None
    commit_id = None
    try:
        actual_commit = current_source_commit()
        actual_tree = current_source_tree()
        if source_tree is not None and source_tree != actual_tree:
            raise ValueError("Source tree changed during the build")
        source_tree = actual_tree
        if source_commit is not None and source_commit != actual_commit:
            raise ValueError("Source HEAD changed during the build")
        source_commit = actual_commit
        require_clean_source()
        logd_path, metadata_path, commit_id = diagnostic_paths_for_commit(source_commit[:8])
        # Do not silently replace evidence for an already-diagnosed source.
        if any(DIAGNOSTIC_DIR.glob(f"build-{commit_id}*")):
            metadata_path = None
            raise ValueError("Diagnostics already exist for this source commit; preserve them and use a fresh source commit")

        summary = ["Tent of Trials - Build Summary", f"source_commit: {source_commit}",
                   f"source_tree: {source_tree}",
                   f"format: {safe_logd.FORMAT}",
                   f"total_modules: {len(results)}",
                   f"passed: {sum(1 for _, success, _, _, _ in results if success)}",
                   f"failed: {sum(1 for _, success, _, _, _ in results if not success)}"]
        logs = [f"source_commit: {source_commit}"]
        for name, success, elapsed, output, binary in results:
            label = f"{name}: {'PASS' if success else 'FAIL'} ({elapsed:.2f}s)"
            summary.append(label)
            logs.extend([label, output])
            artifact = repo_relative_metadata_path(binary)
            if artifact:
                summary.append(f"artifact: {artifact}")
                logs.append(f"artifact: {artifact}")
        texts = {
            "build.log": redact_diagnostic_text("\n".join(logs)),
            "build-summary.txt": redact_diagnostic_text("\n".join(summary)),
            "system-info.txt": collect_system_info(),
        }
        key = safe_logd.pack_diagnostic_texts(logd_path, texts)
        if safe_logd.unpack_diagnostic_texts(logd_path, key) != texts:
            raise ValueError("Generated diagnostic round-trip verification failed")
        logd_files = split_diagnostic_logd(logd_path, DIAGNOSTIC_CHUNK_SIZE)
        relpaths = [path.relative_to(ROOT).as_posix() for path in logd_files]
        report = build_diagnostic_report(results, commit_id, logd_relpaths=relpaths,
                                        password=key, chunked=len(logd_files) > 1,
                                        source_commit=source_commit, source_tree=source_tree)
        report["files"] = {name: {"bytes": len(text.encode("utf-8")),
                                  "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
                           for name, text in texts.items()}
        report["artifact_sha256"] = {path.relative_to(ROOT).as_posix():
                                      hashlib.sha256(path.read_bytes()).hexdigest()
                                      for path in logd_files}
        write_diagnostic_report(metadata_path, report)
        if not commit_diagnostic_artifacts([metadata_path, *logd_files], commit_id):
            return False
        print("    Safe diagnostics verified. JSON contains the public decryption key.")
        print("    Format: safe-logd-v1; not compatible with Encryptly.")
        return True
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        message = redact_diagnostic_text(str(error))
        print(f"    Diagnostic failure: {message}")
        # Failure JSON is evidence of the failure, never a replacement encrypted log.
        if metadata_path is not None and not metadata_path.exists() and not metadata_path.is_symlink():
            report = build_diagnostic_report(results, commit_id, logd_error=message,
                                            message_blocker=DIAGNOSTIC_BLOCKER_MESSAGE,
                                            source_commit=source_commit, source_tree=source_tree)
            write_diagnostic_report(metadata_path, report)
            commit_diagnostic_artifacts([metadata_path], commit_id)
        return False


def print_summary(results: list[tuple[str, bool, float, str, Optional[str]]]):
    print(f"  {color('Build Summary', Colors.BOLD)}")

    total = len(results)
    passed = sum(1 for _, s, _, _, _ in results if s)
    failed = total - passed
    total_time = sum(t for _, _, t, _, _ in results)

    for name, success, elapsed, output, binary in results:
        status_icon = color("✓", Colors.GREEN) if success else color("✗", Colors.RED)
        status_text = color("PASS", Colors.GREEN) if success else color("FAIL", Colors.RED)
        time_str = f"{elapsed:.1f}s" if elapsed < 60 else f"{elapsed / 60:.1f}m"

        print(f"\n  {status_icon}  {color(name + ':', Colors.BOLD)} {status_text}  ({time_str})")
        if binary:
            print(f"       artifact: {color(binary, Colors.GRAY)}")
        if not success and output:

            lines = output.strip().split("\n")
            print(f"       {color('last output:', Colors.RED)}")
            for line in lines[-5:]:
                print(f"       {color(line, Colors.GRAY)}")

    print(f"\n  {color('─' * 40, Colors.GRAY)}")
    print(f"  {color('Total:', Colors.BOLD)} {total} modules, "
          f"{color(str(passed) + ' passed', Colors.GREEN)}, "
          f"{color(str(failed) + ' failed', Colors.RED)}, "
          f"{total_time:.1f}s total")

def main():
    parser = argparse.ArgumentParser(
        description="Tent of Trials  -  Multi-Language Build System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 build.py                    Build all modules
  python3 build.py -m backend         Build only backend
  python3 build.py -m frontend,market Build frontend and market
  python3 build.py --clean            Clean all artifacts
  python3 build.py --release          Release build (Rust only)
  python3 build.py --verbose          Verbose output

Diagnostic bundle:
  python3 build.py
        """,
    )
    parser.add_argument(
        "-m", "--module",
        help="Module(s) to build (comma-separated, or 'all')",
        default="all",
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Clean build artifacts instead of building",
    )
    parser.add_argument(
        "--release", action="store_true",
        help="Build in release mode (Rust backend)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed build output",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available modules and exit",
    )

    args = parser.parse_args()

    print(f"\n  {color('Tent of Trials: building', Colors.CYAN)}")
    print(f"  Working directory: {ROOT}")
    print()

    if args.list:
        print(f"  {color('Available modules:', Colors.BOLD)}")
        for m in MODULES:
            print(f"    {color(m.name, Colors.CYAN)} ({m.language})")
            print(f"      dir: {m.dir.relative_to(ROOT)}")
            print(f"      build: {' '.join(m.build_cmd)}")
        return 0

    print(f"  {color('Checking prerequisites...', Colors.GRAY)}")
    missing = check_prerequisites()
    if missing:
        print(f"\n  {color('⚠ Some tools missing  -  will try anyway:', Colors.YELLOW)}")
        for m in missing:
            print(f"    {m}")

        msg = "Not all modules will build. That's fine."
        print(f"  {color(msg, Colors.GRAY)}")
    else:
        print(f"  {color('✓ All prerequisites found', Colors.GREEN)}")
    if args.module == "all":
        selected = MODULES
    else:
        names = [n.strip() for n in args.module.split(",")]
        selected = [m for m in MODULES if m.name in names]
        not_found = set(names) - {m.name for m in MODULES}
        if not_found:
            print(f"  {color('✗ Unknown modules:', Colors.RED)} {', '.join(not_found)}")
            print(f"    Available: {', '.join(m.name for m in MODULES)}")
            return 1

    if not selected:
        print(f"  No modules selected.")
        return 0

    if args.clean:
        # Validate all diagnostic deletion targets before cleaning any module.
        try:
            validate_diagnostic_directory()
            diagnostic_artifacts = [ROOT / "build.logd"]
            if DIAGNOSTIC_DIR.exists():
                prefix = "build-" + "[0-9a-f]" * 8
                for pattern in (prefix + ".logd", prefix + "-part*.logd",
                                prefix + ".json", prefix + "-metadata.json"):
                    diagnostic_artifacts.extend(DIAGNOSTIC_DIR.glob(pattern))
            if any(path.is_symlink() or (path.exists() and not path.is_file())
                   for path in diagnostic_artifacts):
                raise ValueError("Refusing to clean symlink or non-file diagnostic entries")
        except (OSError, ValueError) as error:
            print(f"  Cannot clean diagnostics: {redact_diagnostic_text(str(error))}")
            return 1
        print(f"\n  {color('Cleaning build artifacts...', Colors.YELLOW)}")
        for module in selected:
            clean_module(module, args.verbose)
        for artifact in diagnostic_artifacts:
            if artifact.exists():
                artifact.unlink()
                print(f"  {color('▸', Colors.YELLOW)} Removed {artifact.relative_to(ROOT)}")
        print(f"\n  {color('Clean complete.', Colors.GREEN)}")
        return 0

    # Capture the source revision before any module command; generated artifacts
    # name this source commit, not the later automatic diagnostics commit.
    try:
        source_commit = current_source_commit()
        source_tree = current_source_tree()
        require_clean_source()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"  Cannot build source-matched diagnostics: {redact_diagnostic_text(str(error))}")
        return 1

    print(f"\n  {color(f'Building {len(selected)} module(s) | release={args.release}', Colors.GRAY)}")

    results: list[tuple[str, bool, float, str, Optional[str]]] = []

    for module in selected:
        success, elapsed, output = build_module(module, args.release, args.verbose)
        binary = verify_binary(module) if success else None
        results.append((module.name, success, elapsed, output, binary))

    print_summary(results)

    diagnostics_ok = generate_logd(results, args.verbose, source_commit=source_commit, source_tree=source_tree)

    return 0 if diagnostics_ok and all(r[1] for r in results) else 1

if __name__ == "__main__":
    sys.exit(main())
