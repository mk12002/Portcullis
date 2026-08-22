---
title: Portcullis
emoji: 🏰
colorFrom: indigo
colorTo: gray
sdk: gradio
app_file: app.py
pinned: false
license: apache-2.0
short_description: Static security scanner for CI/CD pipelines (GitHub/GitLab/Jenkins)
---

# 🏰 Portcullis — CI/CD pipeline security scanner (web demo)

Paste a CI/CD pipeline definition (GitHub Actions, GitLab CI, or Jenkins) and
get Portcullis's prioritized security findings, score, and full HTML report.
Runs the same engine as the CLI — **statically and offline**; it never executes
your pipeline.

## Deploying this to a Hugging Face Space (you)

1. Create a new Space at <https://huggingface.co/new-space> → **SDK: Gradio**.
2. Push the contents of this `demo/` folder to the Space repo (this `README.md`
   provides the Space metadata header above, `app.py` is the app, and
   `requirements.txt` the deps).
3. The Space builds and serves the app; link it from the README/blog as
   **"Try Portcullis →"**.

## Running locally

```bash
pip install -r demo/requirements.txt   # or: pip install -e . gradio
python demo/app.py                      # opens http://127.0.0.1:7860
```

> The demo writes your pasted text to a temporary directory and scans it; nothing
> is stored or sent anywhere. The rendered report is additionally sandboxed in an
> iframe as defense-in-depth.
