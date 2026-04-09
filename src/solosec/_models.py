from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, TypedDict

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
OutputFormat = Literal["json", "bash"]

DEFAULT_FAIL_ON_SEVERITIES: Final[tuple[Severity, ...]] = ("CRITICAL", "HIGH")


class BaseFindingDict(TypedDict):
    tool: str
    severity: Severity
    file: str
    description: str


class FindingDict(BaseFindingDict, total=False):
    line: int
    fix: str
    rule_id: str
    snippet: str
    solution: str


class ReportSummaryDict(TypedDict):
    total_issues: int
    tools_run: list[str]


class AggregateReportDict(TypedDict):
    summary: ReportSummaryDict
    findings: list[FindingDict]


SummaryCounts = dict[Severity, int]
SummaryBreakdown = dict[Severity, dict[str, int]]


@dataclass(slots=True, frozen=True)
class Finding:
    tool: str
    severity: Severity
    file: str
    description: str
    line: int | None = None
    fix: str | None = None
    rule_id: str | None = None
    snippet: str | None = None
    solution: str | None = None

    def to_dict(self) -> FindingDict:
        finding: FindingDict = {
            "tool": self.tool,
            "severity": self.severity,
            "file": self.file,
            "description": self.description,
        }
        if self.line is not None:
            finding["line"] = self.line
        if self.fix is not None:
            finding["fix"] = self.fix
        if self.rule_id is not None:
            finding["rule_id"] = self.rule_id
        if self.snippet is not None:
            finding["snippet"] = self.snippet
        if self.solution is not None:
            finding["solution"] = self.solution
        return finding


@dataclass(slots=True, frozen=True)
class ToolSelection:
    trivy: bool = True
    semgrep: bool = True
    gitleaks: bool = True
    zap: bool = True

    def as_dict(self) -> dict[str, bool]:
        return {
            "trivy": self.trivy,
            "semgrep": self.semgrep,
            "gitleaks": self.gitleaks,
            "zap": self.zap,
        }


@dataclass(slots=True, frozen=True)
class ResolvedConfig:
    url: str
    exclude_dirs: list[str]
    tools: ToolSelection


@dataclass(slots=True, frozen=True)
class CliOptions:
    project_root: Path
    cli_url: str
    config_path: Path | None = None


@dataclass(slots=True, frozen=True)
class AggregateCliOptions:
    report_dir: Path
    output_file: Path


@dataclass(slots=True)
class HumanSummary:
    counts: SummaryCounts = field(
        default_factory=lambda: {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "UNKNOWN": 0,
        }
    )
    breakdown: SummaryBreakdown = field(
        default_factory=lambda: {
            "CRITICAL": {},
            "HIGH": {},
            "MEDIUM": {},
            "LOW": {},
            "INFO": {},
            "UNKNOWN": {},
        }
    )
    total: int = 0
