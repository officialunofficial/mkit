#!/usr/bin/env python3
"""Apply a requested minimum only to the primitives crate, never dependencies."""
import os
import sys

args = sys.argv[1:]
if "--crate-name" in args and args[args.index("--crate-name") + 1] == "mkit_primitives":
    level = os.environ["MKIT_PRIMITIVES_MIN_STABILITY"]
    if level not in ("BETA", "GAMMA", "DELTA", "EPSILON", "RESERVED"):
        sys.exit("invalid primitives stability level")
    args += ["--cfg", f"commonware_stability_{level}"]
os.execvp(args[0], args)
