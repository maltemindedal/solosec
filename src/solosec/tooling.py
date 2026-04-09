from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ZAP_IMAGE: Final[str] = "ghcr.io/zaproxy/zaproxy:stable"


@dataclass(slots=True, frozen=True)
class ToolRunResult:
    name: str
    returncode: int | None
    report_path: Path
    accepted_returncodes: frozenset[int]
    warning: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode in self.accepted_returncodes

    @property
    def report_created(self) -> bool:
        return self.report_path.exists()


@dataclass(slots=True, frozen=True)
class CommandResult:
    returncode: int | None
    warning: str | None = None


def ensure_report_dir(project_root: str | Path) -> Path:
    root = Path(project_root).resolve()
    report_dir = root / ".security_reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    gitignore_path = root / ".gitignore"
    if gitignore_path.exists():
        existing_lines = gitignore_path.read_text(encoding="utf-8").splitlines()
        if not any(line.strip() == ".security_reports/" for line in existing_lines):
            with gitignore_path.open("a", encoding="utf-8") as handle:
                if existing_lines and existing_lines[-1].strip():
                    handle.write("\n")
                handle.write(".security_reports/\n")
    return report_dir


def _run_command(
    args: list[str],
    *,
    cwd: Path,
    stderr_to_devnull: bool = False,
    env_overrides: dict[str, str] | None = None,
) -> CommandResult:
    environment = os.environ.copy()
    if env_overrides is not None:
        environment.update(env_overrides)

    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd),
            env=environment,
            check=False,
            stderr=subprocess.DEVNULL if stderr_to_devnull else None,
        )
    except FileNotFoundError:
        return CommandResult(returncode=None, warning=f"{args[0]} was not found on PATH.")

    return CommandResult(returncode=completed.returncode)


def _prettify_json(path: Path) -> None:
    if not path.exists():
        return
    try:
        raw_data: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return
    path.write_text(json.dumps(raw_data, indent=2, ensure_ascii=False), encoding="utf-8")


def run_trivy(
    project_root: str | Path, report_dir: str | Path, exclude_dirs: list[str]
) -> ToolRunResult:
    report_path = Path(report_dir) / "trivy.json"
    command = ["trivy", "fs", ".", "--format", "json", "--output", str(report_path), "--quiet"]
    if exclude_dirs:
        command.extend(["--skip-dirs", ",".join(exclude_dirs)])
    result = _run_command(command, cwd=Path(project_root).resolve())
    return ToolRunResult(
        name="Trivy",
        returncode=result.returncode,
        report_path=report_path,
        accepted_returncodes=frozenset({0}),
        warning=result.warning,
    )


def run_semgrep(
    project_root: str | Path, report_dir: str | Path, exclude_dirs: list[str]
) -> ToolRunResult:
    report_path = Path(report_dir) / "semgrep.json"
    command = [
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        "--output",
        str(report_path),
        "--quiet",
        ".",
    ]
    for exclude_dir in exclude_dirs:
        if exclude_dir:
            command.extend(["--exclude", exclude_dir])
    result = _run_command(
        command,
        cwd=Path(project_root).resolve(),
        stderr_to_devnull=True,
        env_overrides={"PYTHONUTF8": "1"},
    )
    _prettify_json(report_path)
    return ToolRunResult(
        name="Semgrep",
        returncode=result.returncode,
        report_path=report_path,
        accepted_returncodes=frozenset({0, 1}),
        warning=result.warning,
    )


def run_gitleaks(
    project_root: str | Path, report_dir: str | Path, exclude_dirs: list[str]
) -> ToolRunResult:
    report_path = Path(report_dir) / "gitleaks.json"
    command = [
        "gitleaks",
        "detect",
        "--source",
        ".",
        "--no-git",
        "--report-path",
        str(report_path),
        "--exit-code",
        "0",
    ]
    for exclude_dir in exclude_dirs:
        if exclude_dir:
            command.extend(["--exclude-path", exclude_dir])
    result = _run_command(command, cwd=Path(project_root).resolve(), stderr_to_devnull=True)
    return ToolRunResult(
        name="Gitleaks",
        returncode=result.returncode,
        report_path=report_path,
        accepted_returncodes=frozenset({0}),
        warning=result.warning,
    )


def rewrite_zap_target(url: str) -> str:
    if "localhost" in url or "127.0.0.1" in url:
        return url.replace("localhost", "host.docker.internal").replace(
            "127.0.0.1", "host.docker.internal"
        )
    return url


def resolve_host_report_dir(report_dir: str | Path) -> Path:
    report_path = Path(report_dir).resolve()
    if host_report_dir := os.environ.get("SOLOSEC_HOST_REPORT_DIR"):
        return Path(host_report_dir)
    if host_workspace := os.environ.get("SOLOSEC_HOST_WORKSPACE"):
        return Path(host_workspace) / ".security_reports"
    if github_workspace := os.environ.get("GITHUB_WORKSPACE"):
        return Path(github_workspace) / ".security_reports"
    return report_path


def run_zap(report_dir: str | Path, url: str) -> ToolRunResult:
    report_path = Path(report_dir) / "zap.json"
    host_report_dir = resolve_host_report_dir(report_dir)
    target = rewrite_zap_target(url)
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{host_report_dir}:/zap/wrk/:rw",
        "-t",
        ZAP_IMAGE,
        "zap-full-scan.py",
        "-t",
        target,
        "-J",
        "zap.json",
        "-r",
        "zap.html",
        "-I",
    ]
    result = _run_command(command, cwd=Path(report_dir).resolve())
    return ToolRunResult(
        name="ZAP",
        returncode=result.returncode,
        report_path=report_path,
        accepted_returncodes=frozenset({0}),
        warning=result.warning,
    )
