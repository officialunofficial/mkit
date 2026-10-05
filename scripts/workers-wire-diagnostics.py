#!/usr/bin/env python3
"""Retain wire runtime evidence even when existing replay-safe retries recover."""
# SPDX-License-Identifier: MIT OR Apache-2.0
import argparse
import json
from pathlib import Path
import re


RETRY = re.compile(r"^([a-z0-9_.]+): retry [0-9]+:", re.MULTILINE)
LOSS = "Network connection lost"


def collect(root):
    phases = {}
    for pattern in ("runner-*.log", "wrangler.log", "wrangler-debug.log", "http-*.jsonl"):
        for path in sorted(root.rglob(pattern)):
            phase = path.parent.relative_to(root).as_posix()
            row = phases.setdefault(phase, {"phase": phase, "retries": 0, "cases": {},
                "runtime_loss_lines": 0, "runner_loss_lines": 0, "traced_losses": 0})
            if path.name.startswith("http-"):
                for line in path.read_text().splitlines():
                    record = json.loads(line)
                    row["traced_losses"] += int(record.get("connection_loss", False))
            else:
                text = path.read_text(errors="replace")
                if path.name.startswith("runner-"):
                    for case in RETRY.findall(text):
                        row["retries"] += 1
                        row["cases"][case] = row["cases"].get(case, 0) + 1
                    row["runner_loss_lines"] += sum(LOSS in line for line in text.splitlines())
                else:
                    row["runtime_loss_lines"] += sum(LOSS in line for line in text.splitlines())
    rows = list(phases.values())
    totals = {key: sum(row[key] for row in rows) for key in (
        "retries", "runtime_loss_lines", "runner_loss_lines", "traced_losses")}
    return {"keep": any(totals.values()), "totals": totals, "phases": rows}


def markdown(report):
    lines = ["### Workers wire connection diagnostics", "",
             "| Phase | Retries | Traced lost responses | Runtime loss lines | Runner loss lines |",
             "| --- | ---: | ---: | ---: | ---: |"]
    for row in report["phases"]:
        lines.append(f'| `{row["phase"]}` | {row["retries"]} | {row["traced_losses"]} | '
                     f'{row["runtime_loss_lines"]} | {row["runner_loss_lines"]} |')
    totals = report["totals"]
    lines += [f'| **Total** | **{totals["retries"]}** | **{totals["traced_losses"]}** | '
              f'**{totals["runtime_loss_lines"]}** | **{totals["runner_loss_lines"]}** |', "",
              "Runtime/runner counts are literal log lines, not unique requests; they can overlap.",
              "Retries count stderr retry records, including retries in cases that later fail.", ""]
    for row in report["phases"]:
        for case, count in sorted(row["cases"].items()):
            lines.append(f'- `{row["phase"]}` / `{case}`: {count} retries')
    lines += ["", "Download `workers-wire-logs` for phase logs, request/replay hashes, "
              "runtime versions and server/alarm output when losses or retries occur."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--keep-file", type=Path)
    args = parser.parse_args()
    report = collect(args.root)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.summary:
        with args.summary.open("a") as summary:
            summary.write(markdown(report))
    if args.github_output:
        with args.github_output.open("a") as output:
            output.write(f'keep={str(report["keep"]).lower()}\n')
    if args.keep_file and report["keep"]:
        args.keep_file.touch()


if __name__ == "__main__":
    main()
