"""GitHub Actions parser: ``.github/workflows/*.y*ml`` → normalized Pipeline.

Resolves triggers (with untrusted-input/privileged classification), top-level
and job permissions, steps with ``uses``/``run``/``env``/``with``, matrix flags,
container/service images, and reusable-workflow job calls (followed shallowly:
the reference itself is analyzed, not the called workflow's content).
"""

from __future__ import annotations

import re
from typing import Any

from portcullis.core.models import (
    ImageRef,
    Job,
    Pipeline,
    Step,
    Trigger,
    UsesRef,
)
from portcullis.platforms.base import (
    ParseError,
    Platform,
    as_str_dict,
    item_line,
    key_line,
    load_yaml,
    value_line,
)

WORKFLOW_PATH_RE = re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$")

# Events where attacker-controllable input reaches a workflow that runs with
# secrets and (by default) a write-capable token.
PRIVILEGED_UNTRUSTED_EVENTS = {
    "pull_request_target",
    "workflow_run",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
    "pull_request_review",
    "pull_request_review_comment",
}
# Events carrying attacker input but running *without* secrets by default.
INPUT_ONLY_UNTRUSTED_EVENTS = {"pull_request"}

GITHUB_HOSTED_RUNNER_RE = re.compile(
    r"^(ubuntu|windows|macos)-", re.IGNORECASE
)

# `with: ref:` values that check out attacker-controlled PR-head code.
PR_HEAD_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref"
    r"|github\.event\.workflow_run\.head_(branch|sha)",
)


class GitHubActionsPlatform(Platform):
    name = "github"

    def matches(self, rel_path: str) -> bool:
        return bool(WORKFLOW_PATH_RE.search(rel_path))

    def parse(self, text: str, rel_path: str) -> Pipeline:
        data = load_yaml(text, rel_path)
        if not isinstance(data, dict):
            raise ParseError(f"{rel_path}: workflow root is not a mapping")

        pipeline = Pipeline(
            platform=self.name,
            file_path=rel_path,
            capabilities=frozenset({"permissions", "actions", "expressions"}),
        )

        pipeline.triggers = self._parse_triggers(data, pipeline)
        # 'on' may parse as boolean True under YAML 1.1-style loaders; handled
        # in _parse_triggers. Permissions and env are plain values.
        pipeline.permissions = data.get("permissions")
        if "permissions" in data:
            pipeline.permissions_line = key_line(data, "permissions")
        pipeline.env = as_str_dict(data.get("env"))

        untrusted = [t for t in pipeline.triggers if t.untrusted_privileged]
        reason = (
            f"workflow triggered by {', '.join(sorted({t.event for t in untrusted}))}: "
            "attacker-controllable input reaches jobs that run with secrets access"
            if untrusted
            else ""
        )

        jobs_node = data.get("jobs")
        if isinstance(jobs_node, dict):
            for job_key, job_node in jobs_node.items():
                if not isinstance(job_node, dict):
                    pipeline.warnings.append(f"job '{job_key}' is not a mapping; skipped")
                    continue
                job = self._parse_job(str(job_key), job_node, jobs_node)
                job.reachable_from_untrusted = bool(untrusted)
                job.untrusted_reason = reason
                pipeline.jobs.append(job)
        return pipeline

    # -- internals ------------------------------------------------------------

    def _parse_triggers(self, data: Any, pipeline: Pipeline) -> list[Trigger]:
        on_key = "on" if "on" in data else (True if True in data else None)
        if on_key is None:
            return []
        on = data[on_key]
        line = key_line(data, on_key)
        events: list[tuple[str, dict[str, Any], int]] = []
        if isinstance(on, str):
            events.append((on, {}, line))
        elif isinstance(on, list):
            for i, ev in enumerate(on):
                events.append((str(ev), {}, item_line(on, i, line)))
        elif isinstance(on, dict):
            for ev, quals in on.items():
                events.append(
                    (str(ev), as_str_dict(quals), key_line(on, ev, line))
                )
        else:
            pipeline.warnings.append("unrecognized 'on:' shape")
            return []

        triggers = []
        for event, quals, ev_line in events:
            triggers.append(
                Trigger(
                    event=event,
                    line=ev_line,
                    qualifiers=quals,
                    untrusted_privileged=event in PRIVILEGED_UNTRUSTED_EVENTS,
                    untrusted_input=event in PRIVILEGED_UNTRUSTED_EVENTS
                    or event in INPUT_ONLY_UNTRUSTED_EVENTS,
                )
            )
        return triggers

    def _parse_job(self, name: str, node: dict, jobs_node: Any) -> Job:
        job = Job(
            name=name,
            line=key_line(jobs_node, name),
            key_path=f"jobs.{name}",
            permissions=node.get("permissions"),
            permissions_line=key_line(node, "permissions", 0) if "permissions" in node else 0,
            condition=str(node["if"]) if "if" in node else None,
            env=as_str_dict(node.get("env")),
            matrix=isinstance(node.get("strategy"), dict)
            and "matrix" in node["strategy"],
        )

        runs_on = node.get("runs-on")
        if isinstance(runs_on, str):
            job.runs_on = [runs_on]
        elif isinstance(runs_on, list):
            job.runs_on = [str(r) for r in runs_on]

        container = node.get("container")
        if isinstance(container, str):
            job.images.append(ImageRef(container, value_line(node, "container"), "container"))
        elif isinstance(container, dict) and isinstance(container.get("image"), str):
            job.images.append(
                ImageRef(container["image"], value_line(container, "image"), "container")
            )
        services = node.get("services")
        if isinstance(services, dict):
            for svc in services.values():
                if isinstance(svc, dict) and isinstance(svc.get("image"), str):
                    job.images.append(
                        ImageRef(svc["image"], value_line(svc, "image"), "service")
                    )

        # Reusable-workflow call: normalize as a single pseudo-step so pinning
        # rules see the reference. Followed shallowly by design (documented).
        if isinstance(node.get("uses"), str):
            uses_line = value_line(node, "uses", job.line)
            job.steps.append(
                Step(
                    name=f"reusable workflow: {node['uses']}",
                    line=uses_line,
                    key_path=f"{job.key_path}.uses",
                    uses=_parse_uses(node["uses"], uses_line),
                    with_=as_str_dict(node.get("with")),
                    secrets=node.get("secrets"),
                )
            )
            return job

        steps_node = node.get("steps")
        if isinstance(steps_node, list):
            for idx, step_node in enumerate(steps_node):
                if not isinstance(step_node, dict):
                    continue
                job.steps.append(
                    self._parse_step(idx, step_node, steps_node, job.key_path)
                )
        return job

    def _parse_step(self, idx: int, node: dict, seq: Any, job_path: str) -> Step:
        line = item_line(seq, idx)
        uses = None
        if isinstance(node.get("uses"), str):
            uses = _parse_uses(node["uses"], value_line(node, "uses", line))
        run = node.get("run")
        return Step(
            name=str(node.get("name") or (uses.raw if uses else f"step[{idx}]")),
            line=line,
            key_path=f"{job_path}.steps[{idx}]",
            index=idx,
            uses=uses,
            run=str(run) if run is not None else None,
            run_line=key_line(node, "run", line) if run is not None else 0,
            env=as_str_dict(node.get("env")),
            with_=as_str_dict(node.get("with")),
            shell=str(node["shell"]) if "shell" in node else None,
        )


def _parse_uses(raw: str, line: int) -> UsesRef:
    raw = raw.strip()
    if raw.startswith("docker://"):
        ref = raw[len("docker://") :]
        name, _, version = ref.partition("@")
        return UsesRef(raw=raw, name=f"docker://{name}", version=version or None, line=line)
    name, _, version = raw.partition("@")
    return UsesRef(raw=raw, name=name, version=version or None, line=line)


def is_pr_head_checkout(step: Step) -> bool:
    """Does this step check out attacker-controlled PR-head code?

    Matches actions/checkout with a PR-head ref, or raw git commands fetching
    PR head refs inside run scripts.
    """
    if step.uses and step.uses.name == "actions/checkout":
        ref = str(step.with_.get("ref", ""))
        if PR_HEAD_REF_RE.search(ref):
            return True
    if step.run:
        if PR_HEAD_REF_RE.search(step.run) and re.search(
            r"\bgit\s+(checkout|fetch|pull)\b|\bgh\s+pr\s+checkout\b", step.run
        ):
            return True
        if re.search(r"refs/pull/[^ ]*/(head|merge)", step.run):
            return True
    return False


ARTIFACT_DOWNLOAD_ACTIONS = {
    "actions/download-artifact",
    "dawidd6/action-download-artifact",
}


def is_artifact_download(step: Step) -> bool:
    """Does this step pull artifacts produced by another (possibly untrusted) run?"""
    if step.uses and step.uses.name in ARTIFACT_DOWNLOAD_ACTIONS:
        return True
    return bool(step.run and re.search(r"\bgh\s+run\s+download\b", step.run))


def persists_credentials(step: Step) -> bool:
    """actions/checkout persists the repo token into .git config unless
    persist-credentials is explicitly false."""
    if not (step.uses and step.uses.name == "actions/checkout"):
        return False
    value = step.with_.get("persist-credentials")
    return not (value is False or str(value).strip().lower() == "false")


def is_self_hosted(job: Job) -> bool:
    """Best-effort: any runs-on label that is not a known GitHub-hosted image."""
    for label in job.runs_on:
        if "${{" in label:
            continue  # expression — can't resolve statically
        if label.lower() == "self-hosted":
            return True
        if not GITHUB_HOSTED_RUNNER_RE.match(label.strip()):
            return True
    return False
