"""Jenkins parser: ``Jenkinsfile`` → normalized Pipeline (best-effort).

Groovy is not cleanly parseable without executing it, which Portcullis will
never do. This parser does a pragmatic *structural* extraction — stages,
``sh`` steps with their Groovy quoting style, agent images, and credentials
bindings — and marks the pipeline ``fidelity="best-effort"`` so rules cap
their confidence at MEDIUM. The reduced fidelity is documented, not masked.
"""

from __future__ import annotations

import posixpath
import re

from portcullis.core.models import ImageRef, Job, Pipeline, Step, Trigger
from portcullis.platforms.base import ParseError, Platform

STAGE_RE = re.compile(r"""\bstage\s*\(\s*['"]([^'"]+)['"]\s*\)""")
SH_START_RE = re.compile(r"""\b(sh|bat|powershell)\s*\(?\s*(?:script\s*:\s*)?('{3}|"{3}|'|")""")
IMAGE_RE = re.compile(r"""\bimage\s+['"]([^'"]+)['"]""")
CRED_ENV_RE = re.compile(
    r"""^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*credentials\s*\(\s*['"]([^'"]+)['"]"""
)
CHANGE_CONTEXT_RE = re.compile(r"\bCHANGE_[A-Z_]+\b|\bchangeRequest\s*\(")


class JenkinsPlatform(Platform):
    name = "jenkins"

    def matches(self, rel_path: str) -> bool:
        base = posixpath.basename(rel_path)
        return base == "Jenkinsfile" or base.startswith("Jenkinsfile.")

    def parse(self, text: str, rel_path: str) -> Pipeline:
        if not re.search(r"\bpipeline\s*\{|\bnode\b|\bstage\s*\(", text):
            raise ParseError(
                f"{rel_path}: no recognizable Jenkins pipeline structure "
                "(expected 'pipeline {', 'node' or 'stage(')"
            )

        pipeline = Pipeline(
            platform=self.name,
            file_path=rel_path,
            capabilities=frozenset({"images", "shell-variables"}),
            fidelity="best-effort",
            warnings=[
                "Jenkinsfile parsed structurally (best-effort); Groovy logic is "
                "not evaluated, so findings are capped at MEDIUM confidence"
            ],
        )

        lines = text.splitlines()
        untrusted = bool(CHANGE_CONTEXT_RE.search(text))
        if untrusted:
            pipeline.triggers.append(
                Trigger(
                    event="change-request",
                    line=1,
                    untrusted_privileged=True,
                    untrusted_input=True,
                )
            )
        else:
            pipeline.triggers.append(Trigger(event="branch", line=1))

        # credentials bindings (environment { X = credentials('id') })
        for ln in lines:
            m = CRED_ENV_RE.match(ln)
            if m:
                pipeline.env[m.group(1)] = f"credentials({m.group(2)})"

        stages: list[tuple[str, int]] = []
        for i, ln in enumerate(lines, start=1):
            m = STAGE_RE.search(ln)
            if m:
                stages.append((m.group(1), i))
        if not stages:
            stages = [("pipeline", 1)]

        jobs: list[Job] = []
        for idx, (stage_name, stage_line) in enumerate(stages):
            end = stages[idx + 1][1] if idx + 1 < len(stages) else len(lines) + 1
            job = Job(
                name=stage_name,
                line=stage_line,
                key_path=f"stage:{stage_name}",
                reachable_from_untrusted=untrusted,
                untrusted_reason=(
                    "Jenkinsfile references change-request context (CHANGE_*): "
                    "multibranch PR builds process attacker-controllable input"
                    if untrusted
                    else ""
                ),
            )
            scan_start = 0 if idx == 0 else stage_line - 1  # pre-stage agent lines → first job
            for i in range(scan_start, min(end - 1, len(lines))):
                m = IMAGE_RE.search(lines[i])
                if m:
                    job.images.append(ImageRef(m.group(1), i + 1, "agent"))
            jobs.append(job)

        for step in self._extract_shell_steps(text):
            owner = jobs[0]
            for job in jobs:
                if job.line <= step.line:
                    owner = job
            step.index = len(owner.steps)
            step.key_path = f"{owner.key_path}.sh[{step.index}]"
            owner.steps.append(step)

        pipeline.jobs = jobs
        return pipeline

    def _extract_shell_steps(self, text: str) -> list[Step]:
        """Find sh/bat/powershell string literals with their quoting style."""
        steps: list[Step] = []
        pos = 0
        while True:
            m = SH_START_RE.search(text, pos)
            if not m:
                break
            delim = m.group(2)
            start = m.end()
            end = text.find(delim, start)
            if end == -1:
                pos = m.end()
                continue
            content = text[start:end]
            line = text.count("\n", 0, m.start()) + 1
            quote = "groovy-double" if '"' in delim else "groovy-single"
            steps.append(
                Step(
                    name=f"{m.group(1)}@{line}",
                    line=line,
                    key_path="",
                    run=content,
                    run_line=line,
                    shell=quote,
                )
            )
            pos = end + len(delim)
        return steps
