"""Tiny terminal output helpers, so every stage prints in the same style."""
from __future__ import annotations

import sys

import pandas as pd


def section(title: str) -> None:
    bar = "=" * 72
    print(f"\n{bar}\n{title}\n{bar}", flush=True)


def step(title: str) -> None:
    print(f"\n--- {title}", flush=True)


def info(msg: str) -> None:
    print(f"  {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"  [warn] {msg}", file=sys.stderr, flush=True)


def headline(label: str, value) -> None:
    print(f"  >> {label}: {value}", flush=True)


def table(df: pd.DataFrame, max_rows: int = 60) -> None:
    """Print a dataframe; long ones are truncated (the full data is always in the output files)."""
    with pd.option_context("display.max_columns", None, "display.width", 200,
                           "display.max_colwidth", 60):
        if len(df) > max_rows:
            print(df.head(max_rows).to_string())
            print(f"  ... {len(df) - max_rows} more row(s)", flush=True)
        else:
            print(df.to_string(), flush=True)
