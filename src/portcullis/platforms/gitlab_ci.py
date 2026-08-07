"""GitLab CI parser: ``.gitlab-ci.yml`` → normalized Pipeline.

Maps jobs, scripts, ``rules``/``only`` trigger conditions, variables, and
images into the shared model. Merge-request-triggered jobs are marked
untrusted-reachable: an MR author controls the input (title, description,
branch name, and the code itself) that those jobs process, and same-project
MR pipelines can expose CI variables to that context.
"""

from __future__ import annotations

import posixpath
from typing import Any

from portcullis.core.models import ImageRef, Job, Pipeline, Step, Trigger
from portcullis.platforms.base import (
    ParseError,
    Platform,
    as_str_dict,
    item_line,
    key_line,
    load_yaml,
    value_line,
)

RESERVED_KEYS = {
    "stages",
    "variables",
    "workflow",
    "default",
    "include",
    "image",
    "services",
    "before_script",
    "after_script",
    "cache",
    "types",
}

MR_MARKERS = ("merge_request_event", "merge_requests")

UNTRUSTED_REASON = (
    "job runs on merge_request_event: the MR author controls the title, "
    "description, branch name, and code this job processes"
)


class GitLabCIPlatform(Platform):
    name = "gitlab"

    def matches(self, rel_path: str) -> bool:
        return posixpath.basename(rel_path) in (".gitlab-ci.yml", ".gitlab-ci.yaml")

    def parse(self, text: str, rel_path: str) -> Pipeline:
        data = load_yaml(text, rel_path)
        if not isinstance(data, dict):
            raise ParseError(f"{rel_path}: .gitlab-ci.yml root is not a mapping")

        pipeline = Pipeline(
            platform=self.name,
            file_path=rel_path,
            capabilities=frozenset({"images", "shell-variables"}),
            env=as_str_dict(data.get("variables")),
        )

        workflow_mr = _rules_mention_mr(
            data.get("workflow", {}).get("rules")
            if isinstance(data.get("workflow"), dict)
            else None
        )
        pipeline.triggers.append(Trigger(event="push", line=1))
        if workflow_mr or any(
            _job_is_mr_triggered(v, workflow_mr) for v in data.values() if isinstance(v, dict)
        ):
            pipeline.triggers.append(
                Trigger(
                    event="merge_request_event",
                    line=1,
                    untrusted_privileged=True,
                    untrusted_input=True,
                )
            )

        global_image = data.get("image")
        global_services = data.get("services")

        for name, node in data.items():
            key = str(name)
            if key in RESERVED_KEYS or key.startswith("."):
                continue
            if not isinstance(node, dict) or not _looks_like_job(node):
                continue
            job = self._parse_job(key, node, data, global_image, global_services)
            if _job_is_mr_triggered(node, workflow_mr):
                job.reachable_from_untrusted = True
                job.untrusted_reason = UNTRUSTED_REASON
            pipeline.jobs.append(job)

        if not pipeline.jobs:
            pipeline.warnings.append("no jobs found in .gitlab-ci.yml")
        return pipeline

    def _parse_job(
        self,
        name: str,
        node: dict,
        root: Any,
        global_image: Any,
        global_services: Any,
    ) -> Job:
        job = Job(
            name=name,
            line=key_line(root, name),
            key_path=name,
            env=as_str_dict(node.get("variables")),
        )

        for img_node, owner, ctx in (
            (node.get("image"), node, "image"),
            (global_image, root, "image"),
        ):
            if img_node is not None:
                job.images.append(_image_ref(img_node, owner, ctx))
                break  # job-level image overrides global
        for svc_source, _owner in ((node.get("services"), node), (global_services, root)):
            if isinstance(svc_source, list):
                for i, svc in enumerate(svc_source):
                    line = item_line(svc_source, i, job.line)
                    if isinstance(svc, str):
                        job.images.append(ImageRef(svc, line, "service"))
                    elif isinstance(svc, dict) and isinstance(svc.get("name"), str):
                        job.images.append(ImageRef(svc["name"], line, "service"))
                break

        idx = 0
        for section in ("before_script", "script", "after_script"):
            entries = node.get(section)
            if isinstance(entries, str):
                entries = [entries]
            if not isinstance(entries, list):
                continue
            seq = node.get(section)
            for i, entry in enumerate(entries):
                line = (
                    item_line(seq, i, key_line(node, section, job.line))
                    if isinstance(seq, list)
                    else value_line(node, section, job.line)
                )
                job.steps.append(
                    Step(
                        name=f"{section}[{i}]",
                        line=line,
                        key_path=f"{name}.{section}[{i}]",
                        index=idx,
                        run=str(entry),
                        run_line=line,
                        shell="sh",
                    )
                )
                idx += 1
        return job


def _image_ref(img_node: Any, owner: Any, ctx: str) -> ImageRef:
    if isinstance(img_node, dict):
        image = str(img_node.get("name", ""))
        return ImageRef(image, value_line(img_node, "name", key_line(owner, ctx)), ctx)
    return ImageRef(str(img_node), value_line(owner, "image", 1), ctx)


def _looks_like_job(node: dict) -> bool:
    return any(k in node for k in ("script", "before_script", "trigger", "extends", "run"))


def _rules_mention_mr(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if isinstance(rule, dict) and "merge_request_event" in str(rule.get("if", "")):
            return True
    return False


def _job_is_mr_triggered(node: dict, workflow_mr: bool) -> bool:
    if _rules_mention_mr(node.get("rules")):
        return True
    only = node.get("only")
    if isinstance(only, list) and any(str(o) in MR_MARKERS for o in only):
        return True
    # With a workflow-level MR rule and no job-level restriction, jobs run in MR pipelines.
    if workflow_mr and "rules" not in node and "only" not in node:
        return True
    return False
