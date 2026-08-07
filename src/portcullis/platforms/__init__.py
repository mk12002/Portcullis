"""Platform parsers: each normalizes one CI system into the shared Pipeline model."""

from portcullis.platforms.base import Platform
from portcullis.platforms.github_actions import GitHubActionsPlatform
from portcullis.platforms.gitlab_ci import GitLabCIPlatform
from portcullis.platforms.jenkins import JenkinsPlatform

ALL_PLATFORMS: dict[str, Platform] = {
    "github": GitHubActionsPlatform(),
    "gitlab": GitLabCIPlatform(),
    "jenkins": JenkinsPlatform(),
}

__all__ = ["ALL_PLATFORMS", "Platform"]
