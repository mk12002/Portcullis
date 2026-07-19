"""Taint classification: untrusted sources, run sinks vs env-routed safety."""

from __future__ import annotations

import pytest

from portcullis.core import taint
from portcullis.core.models import Step


def step_with_run(run: str, env: dict | None = None, shell: str | None = None) -> Step:
    return Step(name="s", line=10, key_path="jobs.j.steps[0]", run=run, run_line=10,
                env=env or {}, shell=shell)


@pytest.mark.parametrize(
    "expr",
    [
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.ref",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.discussion.title",
        "github.event.head_commit.message",
        "github.event.workflow_run.head_branch",
        "github.head_ref",
        "format('{0}', github.event.issue.title)",
        "GitHub.Event.Issue.Title",  # case-insensitive
    ],
)
def test_untrusted_sources_classified(expr):
    assert taint.is_github_untrusted(expr)


@pytest.mark.parametrize(
    "expr",
    ["github.sha", "github.repository", "github.actor", "github.run_id",
     "matrix.python", "secrets.MY_TOKEN", "github.event_name"],
)
def test_trusted_context_not_flagged(expr):
    assert not taint.is_github_untrusted(expr)


def test_untrusted_in_run_is_a_sink():
    step = step_with_run('echo "title: ${{ github.event.issue.title }}"')
    hits = taint.github_run_sinks(step)
    assert len(hits) == 1
    assert hits[0].source == "github.event.issue.title"
    assert hits[0].line == 10


def test_same_source_via_env_is_safe():
    step = step_with_run('echo "$TITLE"', env={"TITLE": "${{ github.event.issue.title }}"})
    assert taint.github_run_sinks(step) == []
    assert taint.github_env_routed(step) == ["github.event.issue.title"]


def test_multiline_run_line_offsets():
    step = step_with_run(
        'echo start\necho "${{ github.event.pull_request.title }}"\necho done'
    )
    hits = taint.github_run_sinks(step)
    assert len(hits) == 1
    assert hits[0].line == 12  # block content starts at run_line + 1


def test_gitlab_unquoted_is_sink_quoted_is_not():
    unquoted = step_with_run("echo title is $CI_MERGE_REQUEST_TITLE")
    quoted = step_with_run('echo "title is $CI_MERGE_REQUEST_TITLE"')
    single = step_with_run("echo '$CI_MERGE_REQUEST_TITLE'")
    assert len(taint.gitlab_script_sinks(unquoted)) == 1
    assert taint.gitlab_script_sinks(quoted) == []
    assert taint.gitlab_script_sinks(single) == []  # not expanded at all


def test_gitlab_braced_form_detected():
    step = step_with_run("echo ${CI_COMMIT_MESSAGE} done")
    hits = taint.gitlab_script_sinks(step)
    assert [h.source for h in hits] == ["CI_COMMIT_MESSAGE"]


def test_jenkins_double_quoted_groovy_interpolation_is_sink():
    step = step_with_run("echo Building ${env.CHANGE_TITLE}", shell="groovy-double")
    hits = taint.jenkins_groovy_sinks(step)
    assert [h.source for h in hits] == ["env.CHANGE_TITLE"]


def test_jenkins_single_quoted_is_not_interpolated():
    step = step_with_run("echo Building ${env.CHANGE_TITLE}", shell="groovy-single")
    assert taint.jenkins_groovy_sinks(step) == []


def test_jenkins_params_detected():
    step = step_with_run("deploy ${params.TARGET}", shell="groovy-double")
    hits = taint.jenkins_groovy_sinks(step)
    assert [h.source for h in hits] == ["params.TARGET"]
