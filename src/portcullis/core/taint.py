"""Lightweight untrusted-source → sink reachability analysis.

This is deliberately simple string/context analysis, not full dataflow:
it answers "does an attacker-controllable context value land *directly*
inside a shell command line?" versus the safe pattern of routing it
through ``env:`` and referencing it as a quoted shell variable.
Confidence on findings reflects this simplicity honestly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from portcullis.core.models import Step

# --- GitHub Actions -----------------------------------------------------------
# Attacker-controllable context fields. Entries ending in "." are prefixes that
# cover a whole subtree (e.g. everything under github.event.pull_request.head).
GITHUB_UNTRUSTED_SOURCES: tuple[str, ...] = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.commits",
    "github.event.head_commit.",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.",
    "github.event.workflow_run.head_repository.",
    "github.event.workflow_run.pull_requests",
    "github.event.pages.",
    "github.head_ref",
)

# Trusted context values commonly interpolated — never flagged.
GITHUB_TRUSTED_SOURCES: tuple[str, ...] = (
    "github.sha",
    "github.repository",
    "github.repository_owner",
    "github.actor",
    "github.ref",
    "github.run_id",
    "github.run_number",
    "github.event_name",
    "github.workspace",
)

GITHUB_EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)

# --- GitLab CI ----------------------------------------------------------------
# Variables whose value is controlled by the author of a merge request / commit.
GITLAB_UNTRUSTED_VARS: tuple[str, ...] = (
    "CI_MERGE_REQUEST_TITLE",
    "CI_MERGE_REQUEST_DESCRIPTION",
    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
    "CI_COMMIT_MESSAGE",
    "CI_COMMIT_DESCRIPTION",
    "CI_COMMIT_TAG_MESSAGE",
    "CI_COMMIT_REF_NAME",
)

# --- Jenkins ------------------------------------------------------------------
# Multibranch-pipeline change-request environment (attacker-controllable on PRs).
JENKINS_UNTRUSTED_ENV: tuple[str, ...] = (
    "CHANGE_TITLE",
    "CHANGE_BRANCH",
    "CHANGE_AUTHOR",
    "CHANGE_AUTHOR_DISPLAY_NAME",
    "CHANGE_AUTHOR_EMAIL",
    "BRANCH_NAME",
)

JENKINS_INTERP_RE = re.compile(r"\$\{?\s*(?:env\.|params\.)?([A-Za-z_][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class TaintHit:
    """One untrusted source observed reaching a sink."""

    expression: str  # the raw interpolated expression
    source: str  # which untrusted source matched
    line: int  # approximate file line of the sink
    snippet: str  # the sink line (inert evidence)


def _normalize(expr: str) -> str:
    return re.sub(r"\s+", "", expr).lower()


def github_untrusted_sources(expr: str) -> list[str]:
    """Untrusted GitHub context paths referenced anywhere in an expression.

    Substring matching intentionally catches wrapped forms such as
    ``format('{0}', github.event.issue.title)``.
    """
    norm = _normalize(expr)
    return [s for s in GITHUB_UNTRUSTED_SOURCES if s.rstrip(".") in norm and s in norm + "."]


def is_github_untrusted(expr: str) -> bool:
    return bool(github_untrusted_sources(expr))


def github_run_sinks(step: Step) -> list[TaintHit]:
    """Untrusted ``${{ }}`` expressions interpolated directly into a run script."""
    hits: list[TaintHit] = []
    for line_no, text in step.run_lines():
        for m in GITHUB_EXPR_RE.finditer(text):
            expr = m.group(1).strip()
            for source in github_untrusted_sources(expr):
                hits.append(TaintHit(expr, source.rstrip("."), line_no, text.strip()))
    return hits


def github_env_routed(step: Step) -> list[str]:
    """Untrusted sources safely routed through env: (the recommended pattern)."""
    sources: list[str] = []
    for value in step.env.values():
        for m in GITHUB_EXPR_RE.finditer(str(value)):
            sources.extend(s.rstrip(".") for s in github_untrusted_sources(m.group(1)))
    return sources


def _shell_var_occurrences(text: str, var: str) -> list[bool]:
    """Occurrences of $VAR / ${VAR} in a shell line → quoted-in-double-quotes flags.

    Occurrences inside single quotes are not expanded by the shell and are
    ignored. Returns one bool per expanding occurrence: True if it sits inside
    double quotes (safe from word-splitting/injection-adjacent behavior).
    """
    out: list[bool] = []
    in_single = False
    in_double = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "$" and not in_single:
            rest = text[i + 1 :]
            if rest.startswith("{" + var + "}") or re.match(
                re.escape(var) + r"(?![A-Za-z0-9_])", rest
            ):
                out.append(in_double)
        i += 1
    return out


def gitlab_script_sinks(step: Step) -> list[TaintHit]:
    """MR-author-controlled variables expanded *unquoted* in a script line.

    Double-quoted expansion (``"$CI_MERGE_REQUEST_TITLE"``) is shell-safe and
    not reported; unquoted expansion allows word-splitting/option injection.
    """
    hits: list[TaintHit] = []
    for line_no, text in step.run_lines():
        for var in GITLAB_UNTRUSTED_VARS:
            for quoted in _shell_var_occurrences(text, var):
                if not quoted:
                    hits.append(TaintHit(f"${var}", var, line_no, text.strip()))
    return hits


def jenkins_groovy_sinks(step: Step) -> list[TaintHit]:
    """Untrusted change-request values Groovy-interpolated into a double-quoted sh.

    ``sh "echo ${env.CHANGE_TITLE}"`` interpolates the PR title into the shell
    command string *before* the shell runs — a command-injection sink. The
    single-quoted form leaves ``$VAR`` to the shell (env expansion, safe).
    """
    if step.shell != "groovy-double" or not step.run:
        return []
    hits: list[TaintHit] = []
    for line_no, text in step.run_lines():
        for m in re.finditer(r"\$\{\s*(env|params)\.([A-Za-z_][A-Za-z0-9_]*)[^}]*\}", text):
            scope, name = m.group(1), m.group(2)
            if scope == "env" and name in JENKINS_UNTRUSTED_ENV:
                hits.append(TaintHit(m.group(0), f"env.{name}", line_no, text.strip()))
            elif scope == "params":
                hits.append(TaintHit(m.group(0), f"params.{name}", line_no, text.strip()))
    return hits
