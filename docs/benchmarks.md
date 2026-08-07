# Benchmarks

All numbers are reproducible with the commands shown. Environment: Python 3.11,
a laptop-class machine; your throughput will vary but the shape holds.

## Speed

| Workload | Files | Findings | Time | Throughput |
|---|---|---|---|---|
| Bundled GitHub fixtures | 2 | 11 | **~12 ms** | — |
| Real-world set (10 OSS repos) | 66 | ~130 | **~1.4 s** | ~47 files/s* |
| Synthetic vulnerable workflows | 500 | 2,500 | **~1.4 s** | **~360 files/s** |

\* The real-world set includes git-clone and disk I/O across three platforms;
the synthetic set isolates parse+rules throughput.

Portcullis is single-pass and CPU-light; scanning a typical repository's handful
of pipeline files is effectively instant, and even a monorepo with hundreds of
workflows scans in seconds.

Reproduce the synthetic benchmark:

```python
import time, tempfile
from pathlib import Path
from portcullis.core.engine import scan
from portcullis.core.models import ScanConfig

wf = ("on: pull_request_target\npermissions: write-all\njobs:\n  j:\n"
      "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
with tempfile.TemporaryDirectory() as d:
    wd = Path(d) / ".github" / "workflows"; wd.mkdir(parents=True)
    for i in range(500):
        (wd / f"wf{i}.yml").write_text(wf)
    t = time.time(); r = scan(Path(d), ScanConfig())
    print(len(r.files_scanned), "files in", round(time.time() - t, 2), "s")
```

## Robustness

On the real-world set of 66 files from 10 well-known projects (Flask, FastAPI,
requests, actions/runner, gitlab-runner, jenkinsci/pipeline-examples, …):

- **Zero crashes.** Matrix jobs, reusable workflows, YAML anchors, multi-document
  YAML, and even a deliberately-broken file were all handled.
- **Two genuinely-malformed files** degraded to LOW `R0` findings (warn-and-continue).
- **Zero secret-value leaks** across all four output formats.

## Memory & footprint

- **One runtime dependency** (`ruamel.yaml`) — the whole install is small.
- Memory scales with the size of one file at a time, not the whole tree; the
  parser refuses files over 2 MB and caps YAML expansion at 2M nodes (billion-laughs
  hardening), so a hostile file cannot exhaust memory.

## Accuracy / calibration

Portcullis is calibrated for **low false-positive noise**, not maximal findings.
On the real-world set it agreed directionally with a mature competitor (zizmor)
on which repos were healthy vs. problematic, while producing a prioritized,
lower-volume result (e.g. 81 findings / 0 P0 where a blanket linter reported 230 /
66 "high" on the same repo). Two calibration bugs found on real data were fixed
with regression tests. Full detail: [Real-world Evaluation](EVALUATION.md).

## Supported formats

| Platform | Files | Fidelity |
|---|---|---|
| GitHub Actions | `.github/workflows/*.y*ml` | full |
| GitLab CI | `.gitlab-ci.yml` | full |
| Jenkins | `Jenkinsfile` | best-effort (Groovy; findings capped at MEDIUM confidence) |

Outputs: JSON, self-contained HTML (CSP-hardened), SARIF 2.1.0 (schema-validated),
Markdown.
