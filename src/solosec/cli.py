from __future__ import annotations

import argparse
from pathlib import Path
from typing import cast

from . import aggregate, config, tooling
from ._models import CliOptions, ToolSelection


def _parse_args(argv: list[str] | None = None) -> CliOptions:
    parser = argparse.ArgumentParser(prog="solosec", description="Run the SoloSec security audit.")
    parser.add_argument(
        "-u",
        "--url",
        "-Url",
        "--Url",
        dest="url",
        default="",
        help="Optional DAST target URL",
    )
    parser.add_argument(
        "--project-root",
        default=".",
        help="Project root to scan (defaults to the current working directory)",
    )
    parser.add_argument("--config", default=None, help="Optional path to .solosec.yaml")
    namespace = parser.parse_args(argv)
    project_root = Path(cast(str, namespace.project_root)).resolve()
    config_path_value = cast(str | None, namespace.config)
    return CliOptions(
        project_root=project_root,
        cli_url=cast(str, namespace.url),
        config_path=Path(config_path_value).resolve() if config_path_value is not None else None,
    )


def _print_result(result: tooling.ToolRunResult) -> None:
    if result.ok or result.report_created:
        print("   -> Done.")
        return
    if result.warning is not None:
        print(f"   -> Warning: {result.warning}")
        return
    print(f"   -> Warning: {result.name} exited with status {result.returncode}.")


def _run_enabled_tools(
    project_root: Path, report_dir: Path, tools: ToolSelection, url: str, exclude_dirs: list[str]
) -> None:
    if tools.trivy:
        print("\n[1/4] Running Trivy...")
        _print_result(tooling.run_trivy(project_root, report_dir, exclude_dirs))
    else:
        print("\n[1/4] Skipping Trivy (disabled in .solosec.yaml).")

    if tools.semgrep:
        print("[2/4] Running Semgrep...")
        _print_result(tooling.run_semgrep(project_root, report_dir, exclude_dirs))
    else:
        print("[2/4] Skipping Semgrep (disabled in .solosec.yaml).")

    if tools.gitleaks:
        print("[3/4] Running Gitleaks...")
        _print_result(tooling.run_gitleaks(project_root, report_dir, exclude_dirs))
    else:
        print("[3/4] Skipping Gitleaks (disabled in .solosec.yaml).")

    if tools.zap and url:
        print("[4/4] Running ZAP...")
        rewritten_target = tooling.rewrite_zap_target(url)
        if rewritten_target != url:
            print(
                "      (Detected localhost: switching to "
                "'host.docker.internal' for Docker compatibility)"
            )
            print(f"      Targeting: {rewritten_target}")
        _print_result(tooling.run_zap(report_dir, rewritten_target))
    else:
        print("[4/4] Skipping ZAP (no URL provided or disabled).")


def run_audit(options: CliOptions) -> int:
    resolved = config.resolve_config(
        project_root=options.project_root,
        cli_url=options.cli_url,
        config_path=options.config_path,
    )
    report_dir = tooling.ensure_report_dir(options.project_root)
    output_file = options.project_root / "security_audit.json"

    print("STARTING SECURITY AUDIT")
    print(f"   Target: {options.project_root}")
    if resolved.url:
        print(f"   DAST URL: {resolved.url}")

    _run_enabled_tools(
        options.project_root,
        report_dir,
        resolved.tools,
        resolved.url,
        resolved.exclude_dirs,
    )

    print("\n[*] Generating Final Report...")
    failed = aggregate.generate_report(report_dir=report_dir, output_file=output_file)
    if failed:
        print("\nAUDIT FAILED!")
        print(f"Report saved to: {output_file}")
        return 1

    print("\nAUDIT COMPLETE!")
    print(f"Report saved to: {output_file}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return run_audit(_parse_args(argv))
