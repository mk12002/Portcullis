"""Portcullis — static security analyzer for CI/CD pipeline definitions.

Portcullis parses pipeline files (GitHub Actions, GitLab CI, Jenkins) into a
normalized model and runs a platform-agnostic detection rule set against it.
It is purely static: pipeline files are parsed, never executed, and no network
access is performed at scan time.
"""

__version__ = "0.1.0"
TOOL_NAME = "portcullis"
