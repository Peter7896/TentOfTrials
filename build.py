#!/usr/bin/env python3

import argparse
import datetime
import getpass
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import tempfile
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent
DIAGNOSTIC_DIR = ROOT / "diagnostic"
DIAGNOSTIC_CHUNK_SIZE = 40 * 1024 * 1024


class DiagnosticValidationError(RuntimeError):
    pass


def repo_relative_path(path: Path | str) -> str:
    """Return a deterministic repo-relative path using forward slashes."""
    path_obj = Path(path)
    if not path_obj.is_absolute():
        return str(path).replace("\\", "/")
    try:
        return path_obj.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return f"external/{path_obj.name}"


def _redaction_tokens() -> list[tuple[str, str]]:
    tokens = [
        (str(ROOT), "<repo>"),
        (str(Path.home()), "<home>"),
        (tempfile.gettempdir(), "<temp>"),
        (platform.node(), "<machine>"),
        (getpass.getuser(), "<user>"),
    ]
    for key in ("USERNAME", "USER", "LOGNAME", "COMPUTERNAME"):
        value = os.environ.get(key)
        if value:
            tokens.append((value, f"<{key.lower()}>"))

    expanded: list[tuple[str, str]] = []
    for token, replacement in tokens:
        if not token:
            continue
        expanded.append((token, replacement))
        expanded.append((token.replace("\\", "/"), replacement))
        expanded.append((token.replace("/", "\\"), replacement))

    expanded.sort(key=lambda item: len(item[0]), reverse=True)
    return expanded


def redact_diagnostic_text(value: str) -> str:
    redacted = value
    for token, replacement in _redaction_tokens():
        redacted = redacted.replace(token, replacement)
    return redacted


def sanitize_diagnostic_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: sanitize_diagnostic_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_diagnostic_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_diagnostic_value(item) for item in value]
    if isinstance(value, Path):
        return repo_relative_path(value)
    if isinstance(value, str):
        return redact_diagnostic_text(value)
    return value


def validate_diagnostic_pair(
    metadata_path: Path,
    expected_logd_paths: Optional[list[Path]] = None,
) -> None:
    if not metadata_path.exists():
        raise DiagnosticValidationError(
            f"diagnostic metadata JSON missing: {repo_relative_path(metadata_path)}"
        )

    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DiagnosticValidationError(
            f"diagnostic metadata JSON invalid: {repo_relative_path(metadata_path)}: {exc}"
        ) from exc

    logd_value = metadata.get("diagnostic_logd")
    if not logd_value:
        if metadata.get("diagnostic_logd_error"):
            return
        raise DiagnosticValidationError(
            f"diagnostic_logd missing in {repo_relative_path(metadata_path)}"
        )

    logd_refs = logd_value if isinstance(logd_value, list) else [logd_value]
    normalized_refs: list[str] = []
    for ref in logd_refs:
        if not isinstance(ref, str) or not ref.strip():
            raise DiagnosticValidationError("diagnostic_logd must contain non-empty path strings")
        normalized_ref = ref.replace("\\", "/")
        ref_path = Path(normalized_ref)
        if ref_path.is_absolute() or PureWindowsPath(ref).is_absolute():
            raise DiagnosticValidationError(f"diagnostic_logd must be repo-relative: {ref}")
        artifact_path = ROOT.joinpath(*normalized_ref.split("/"))
        if not artifact_path.exists():
            raise DiagnosticValidationError(f"diagnostic .logd missing: {normalized_ref}")
        normalized_refs.append(normalized_ref)

    if expected_logd_paths is not None:
        expected = [repo_relative_path(path) for path in expected_logd_paths]
        if normalized_refs != expected:
            raise DiagnosticValidationError(
                f"diagnostic_logd mismatch: metadata has {normalized_refs}, expected {expected}"
            )


def current_commit_id() -> str:
    """Return the first 4 bytes (8 hex chars) of HEAD for stable per-commit diagnostics."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=5,
        )
        commit = result.stdout.strip()
        if result.returncode == 0 and len(commit) >= 8:
            return commit[:8]
    except Exception:
        pass
    return "00000000"


def diagnostic_paths_for_commit() -> tuple[Path, Path, str]:
    """Return stable diagnostic artifact paths under diagnostic/ for the current commit."""
    DIAGNOSTIC_DIR.mkdir(parents=True, exist_ok=True)
    commit_id = current_commit_id()
    logd_path = DIAGNOSTIC_DIR / f"build-{commit_id}.logd"
    metadata_path = DIAGNOSTIC_DIR / f"build-{commit_id}.json"
    return logd_path, metadata_path, commit_id


def split_diagnostic_logd(logd_path: Path, chunk_size: int = DIAGNOSTIC_CHUNK_SIZE) -> list[Path]:
    """Split an oversized .logd into numbered .logd chunks and remove the original."""
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
            chunk_path.write_bytes(data)
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

ENCRYPTLY_DIR = ROOT / "tools" / "encryptly"
ENCRYPTLY_BINARIES = {
    "linux-x64": ENCRYPTLY_DIR / "linux-x64" / "encryptly",
    "linux-arm64": ENCRYPTLY_DIR / "linux-arm64" / "encryptly",
    "macos-arm64": ENCRYPTLY_DIR / "macos-arm64" / "encryptly",
    "windows-x64": ENCRYPTLY_DIR / "windows-x64" / "encryptly.exe",
    "windows-arm64": ENCRYPTLY_DIR / "windows-arm64" / "encryptly.exe",
}
LEGACY_ENCRYPTLY_BIN = ENCRYPTLY_DIR / "encryptly"


def _normalize_arch(machine: str) -> Optional[str]:
    machine = machine.lower()
    if machine in {"x86_64", "amd64"}:
        return "x64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    return None


def _normalize_os() -> Optional[str]:
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return None


def detect_encryptly_platform() -> Optional[str]:
    os_name = _normalize_os()
    arch = _normalize_arch(platform.machine())
    if os_name is None or arch is None:
        return None
    return f"{os_name}-{arch}"


def get_encryptly_bin() -> Optional[Path]:
    target = detect_encryptly_platform()
    if target is not None:
        binary = ENCRYPTLY_BINARIES.get(target)
        if binary is not None and binary.exists():
            return binary

    if LEGACY_ENCRYPTLY_BIN.exists():
        return LEGACY_ENCRYPTLY_BIN

    return None


def encryptly_platform_help() -> str:
    detected = detect_encryptly_platform() or "unsupported"
    available = ", ".join(sorted(ENCRYPTLY_BINARIES))
    return f"detected {detected}; available: {available}"

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


def output_supports(text: str) -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "utf-8").lower().replace("_", "-")
    if encoding not in {"utf-8", "utf8", "cp65001"}:
        return False
    try:
        text.encode(encoding)
        return True
    except UnicodeEncodeError:
        return False


def safe_text(text: str, fallback: str) -> str:
    return text if output_supports(text) else fallback


def mark(symbol: str, fallback: str) -> str:
    return safe_text(symbol, fallback)


def rule(width: int) -> str:
    return safe_text("─" * width, "-" * width)


def configure_output_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except Exception:
            pass


configure_output_streams()

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

    print(f"\n  {color(mark('▸', '>'), Colors.CYAN)} Building {color(module.name, Colors.BOLD)} ({module.language})...")

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
            except FileNotFoundError as e:
                return False, time.time() - start, f"npm install command not found: {e}"
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
            return False, time.time() - start, f"CMake configure command not found: {e}"
        if cfg_result.returncode != 0:
            return False, time.time() - start, (
                f"CMake configure failed:\n{cfg_result.stderr}")
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
    print(f"  {color(mark('▸', '>'), Colors.YELLOW)} Cleaning {module.name}...")
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
        print(f"    {color(mark('✗', 'x'), Colors.RED)} Clean failed: {e}")
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


def collect_system_info() -> str:
    lines = [
        "Tent of Trials - System Diagnostic Snapshot",
        "=" * 50,
        f"generated_at: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
        f"hostname: {platform.node()}",
        f"user: {getpass.getuser()}",
        f"python: {sys.version}",
        f"platform: {platform.platform()}",
        f"processor: {platform.processor() or 'unknown'}",
        f"cpu_count: {os.cpu_count()}",
        "",
        "--- uname ---",
    ]
    ok, out = run_cmd(["uname", "-a"])
    lines.append(out if ok else "unavailable")

    lines.extend(["", "--- /etc/os-release ---"])
    try:
        lines.append((Path("/etc/os-release")).read_text(encoding="utf-8", errors="replace").strip())
    except Exception as e:
        lines.append(f"unavailable: {e}")

    lines.extend(["", "--- memory ---"])
    ok, out = run_cmd(["free", "-h"])
    lines.append(out if ok else "unavailable")

    lines.extend(["", "--- disk ---"])
    ok, out = run_cmd(["df", "-h"])
    lines.append(out if ok else "unavailable")

    lines.extend(["", "--- build environment ---"])
    for key in ["SHELL", "LANG", "TERM", "XDG_SESSION_TYPE", "DISPLAY", "EDITOR"]:
        value = os.environ.get(key)
        if value:
            lines.append(f"{key}={value}")

    lines.append("")
    return "\n".join(lines)


def build_diagnostic_report(
    results: list[tuple[str, bool, float, str, Optional[str]]],
    commit_id: str,
    logd_relpaths: Optional[list[str]] = None,
    password: Optional[str] = None,
    logd_error: Optional[str] = None,
    chunked: bool = False,
) -> dict:
    if logd_relpaths:
        logd_relpaths = [repo_relative_path(path) for path in logd_relpaths]

    diagnostic_logd: Optional[str | list[str]]
    if not logd_relpaths:
        diagnostic_logd = None
    elif len(logd_relpaths) == 1:
        diagnostic_logd = logd_relpaths[0]
    else:
        diagnostic_logd = logd_relpaths

    decrypt_target = logd_relpaths[0] if logd_relpaths and len(logd_relpaths) == 1 else None
    if logd_relpaths and len(logd_relpaths) > 1:
        decrypt_target = repo_relative_path(DIAGNOSTIC_DIR / f"build-{commit_id}.logd")

    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "commit": commit_id,
        "diagnostic_logd": diagnostic_logd,
        "diagnostic_logd_error": logd_error,
        "chunked": chunked,
        "chunk_size_bytes": DIAGNOSTIC_CHUNK_SIZE if chunked else None,
        "password": password,
        "decrypt_command": (
            f"encryptly unpack {decrypt_target} <outdir> --password {password}"
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
                "artifact": repo_relative_path(binary) if binary else None,
                "output": redact_diagnostic_text(output),
            }
            for name, success, elapsed, output, binary in results
        ],
        "pr_note": (
            (f"Include the encrypted diagnostic logd artifact(s): {', '.join(logd_relpaths)}. " if logd_relpaths else "Encrypted diagnostic logd artifact was not created; include this JSON report showing why. ")
            + "The encrypted .logd is the required diagnostic content for PR review; this JSON file is metadata. "
            + "Maintainers may ask you to remove these diagnostic artifacts before merging."
        ),
    }
    return sanitize_diagnostic_value(report)


def write_diagnostic_report(metadata_path: Path, report: dict) -> None:
    metadata_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"    {color(mark('✓', '+'), Colors.GREEN)} {metadata_path.relative_to(ROOT)} created")


def generate_logd(
    results: list[tuple[str, bool, float, str, Optional[str]]],
    verbose: bool = False,
) -> bool:
    logd_path, metadata_path, commit_id = diagnostic_paths_for_commit()
    display_logd = logd_path.relative_to(ROOT)
    print(f"\n  {color(mark('▸', '>'), Colors.CYAN)} Finalizing diagnostics for {color(str(display_logd), Colors.BOLD)}...")

    # Always write the JSON report first. The encrypted .logd is useful, but the
    # report is required even when the build failed before compilation started or
    # when encryptly itself is unavailable.
    write_diagnostic_report(metadata_path, build_diagnostic_report(results, commit_id))

    encryptly_bin = get_encryptly_bin()
    if encryptly_bin is None:
        error = f"encryptly binary not found ({encryptly_platform_help()}); cannot create {display_logd}"
        print(f"    {color(mark('✗', 'x'), Colors.RED)} {error}")
        write_diagnostic_report(metadata_path, build_diagnostic_report(results, commit_id, logd_error=error))
        return False

    # Workspace must live under $HOME because encryptly refuses paths outside home.
    home = Path.home()
    workspace = home / ".cache" / "tent-of-trials" / "logd-workspace"
    safe_dir = workspace / "safe"

    try:
        shutil.rmtree(workspace, ignore_errors=True)
        safe_dir.mkdir(parents=True, exist_ok=True)

        (safe_dir / "system-info.txt").write_text(
            redact_diagnostic_text(collect_system_info()), encoding="utf-8"
        )

        summary_lines = [
            "Tent of Trials - Build Summary",
            "=" * 50,
            f"generated_at: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
            f"total_modules: {len(results)}",
            f"passed: {sum(1 for _, s, _, _, _ in results if s)}",
            f"failed: {sum(1 for _, s, _, _, _ in results if not s)}",
            "",
            "module results:",
        ]
        for name, success, elapsed, _, binary in results:
            summary_lines.append(
                f"  {name}: {'PASS' if success else 'FAIL'} ({elapsed:.2f}s)"
                f"{f' [{repo_relative_path(binary)}]' if binary else ''}"
            )
        (safe_dir / "build-summary.txt").write_text(
            "\n".join(summary_lines), encoding="utf-8"
        )

        log_lines = []
        for name, success, elapsed, output, binary in results:
            log_lines.append(
                f"\n{'=' * 50}\n{name} ({'PASS' if success else 'FAIL'}, {elapsed:.2f}s)\n"
                f"{'=' * 50}"
            )
            if binary:
                log_lines.append(f"artifact: {repo_relative_path(binary)}")
            if output:
                log_lines.append(redact_diagnostic_text(output))
        (safe_dir / "build.log").write_text("\n".join(log_lines), encoding="utf-8")

        sr = subprocess.run(
            [
                str(encryptly_bin),
                "pack",
                str(logd_path),
                "--include",
                str(workspace),
                "--max-file-size",
                "10000",
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=300,
        )
        if sr.returncode != 0:
            print(
                f"    {color(mark('✗', 'x'), Colors.RED)} {logd_path.relative_to(ROOT)} creation failed: "
                f"{sr.stderr.strip() or sr.stdout.strip()}"
            )
            if logd_path.exists():
                logd_path.unlink()
            return False

        safe_pw = sr.stdout.strip()
        logd_files = split_diagnostic_logd(logd_path)
        logd_relpaths = [repo_relative_path(path) for path in logd_files]
        decrypt_target = logd_relpaths[0] if len(logd_relpaths) == 1 else repo_relative_path(logd_path)
        write_diagnostic_report(
            metadata_path,
            build_diagnostic_report(
                results,
                commit_id,
                logd_relpaths=logd_relpaths,
                password=safe_pw,
                chunked=len(logd_files) > 1,
            ),
        )

        for path in logd_files:
            size_kb = path.stat().st_size / 1024.0
            print(
                f"    {color(mark('✓', '+'), Colors.GREEN)} {path.relative_to(ROOT)} created "
                f"({size_kb:.1f} KiB)"
            )
        validate_diagnostic_pair(metadata_path, expected_logd_paths=logd_files)
        if len(logd_files) > 1:
            print(
                f"    {color(mark('✓', '+'), Colors.GREEN)} split oversized diagnostic log into "
                f"{len(logd_files)} chunks of at most {DIAGNOSTIC_CHUNK_SIZE // (1024 * 1024)} MiB"
            )
        if safe_pw:
            print()
            print(f"  {color('Password', Colors.BOLD)} - this is required to decrypt the diagnostic log,")
            print(f"             which is required to submit a PR. Upload the")
            print(f"             diagnostic log file(s) and metadata file with this password.")
            if len(logd_files) > 1:
                print(f"             Reassemble chunks in order before unpacking:")
                print(f"             cat {' '.join(logd_relpaths)} > {repo_relative_path(logd_path)}")
            print(f"  {color(safe_pw, Colors.CYAN)}")
            print(f"  {color(f'encryptly unpack {decrypt_target} <outdir> --password {safe_pw}', Colors.GRAY)}")
        return True

    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def print_summary(results: list[tuple[str, bool, float, str, Optional[str]]]):
    print(f"  {color('Build Summary', Colors.BOLD)}")

    total = len(results)
    passed = sum(1 for _, s, _, _, _ in results if s)
    failed = total - passed
    total_time = sum(t for _, _, t, _, _ in results)

    for name, success, elapsed, output, binary in results:
        status_icon = color(mark("✓", "+"), Colors.GREEN) if success else color(mark("✗", "x"), Colors.RED)
        status_text = color("PASS", Colors.GREEN) if success else color("FAIL", Colors.RED)
        time_str = f"{elapsed:.1f}s" if elapsed < 60 else f"{elapsed / 60:.1f}m"

        print(f"\n  {status_icon}  {color(name + ':', Colors.BOLD)} {status_text}  ({time_str})")
        if binary:
            print(f"       artifact: {color(repo_relative_path(binary), Colors.GRAY)}")
        if not success and output:

            lines = output.strip().split("\n")
            print(f"       {color('last output:', Colors.RED)}")
            for line in lines[-5:]:
                print(f"       {color(line, Colors.GRAY)}")

    print(f"\n  {color(rule(40), Colors.GRAY)}")
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
        print(f"\n  {color(safe_text('⚠ Some tools missing  -  will try anyway:', 'WARNING Some tools missing  -  will try anyway:'), Colors.YELLOW)}")
        for m in missing:
            print(f"    {m}")
        print(f"  {color('Not all modules will build. That\'s fine.', Colors.GRAY)}")
    else:
        print(f"  {color(safe_text('✓ All prerequisites found', '+ All prerequisites found'), Colors.GREEN)}")

    if args.module == "all":
        selected = MODULES
    else:
        names = [n.strip() for n in args.module.split(",")]
        selected = [m for m in MODULES if m.name in names]
        not_found = set(names) - {m.name for m in MODULES}
        if not_found:
            print(f"  {color(safe_text('✗ Unknown modules:', 'x Unknown modules:'), Colors.RED)} {', '.join(not_found)}")
            print(f"    Available: {', '.join(m.name for m in MODULES)}")
            return 1

    if not selected:
        print(f"  No modules selected.")
        return 0

    if args.clean:
        print(f"\n  {color('Cleaning build artifacts...', Colors.YELLOW)}")
        for module in selected:
            clean_module(module, args.verbose)

        diagnostic_artifacts = [ROOT / "build.logd"]
        if DIAGNOSTIC_DIR.exists():
            diagnostic_artifacts.extend(DIAGNOSTIC_DIR.glob("build-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].logd"))
            diagnostic_artifacts.extend(DIAGNOSTIC_DIR.glob("build-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-part*.logd"))
            diagnostic_artifacts.extend(DIAGNOSTIC_DIR.glob("build-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].json"))
            diagnostic_artifacts.extend(DIAGNOSTIC_DIR.glob("build-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-metadata.json"))
        for artifact in diagnostic_artifacts:
            if artifact.exists():
                if artifact.is_dir():
                    shutil.rmtree(artifact)
                else:
                    artifact.unlink()
                print(f"  {color(mark('▸', '>'), Colors.YELLOW)} Removed {artifact.relative_to(ROOT)}")
        print(f"\n  {color('Clean complete.', Colors.GREEN)}")
        return 0

    print(f"\n  {color(f'Building {len(selected)} module(s) | release={args.release}', Colors.GRAY)}")

    results: list[tuple[str, bool, float, str, Optional[str]]] = []

    for module in selected:
        success, elapsed, output = build_module(module, args.release, args.verbose)
        binary = verify_binary(module) if success else None
        results.append((module.name, success, elapsed, output, binary))

    print_summary(results)

    generate_logd(results, args.verbose)

    return 0 if all(r[1] for r in results) else 1

if __name__ == "__main__":
    sys.exit(main())
