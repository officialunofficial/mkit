#!/usr/bin/env python3
"""Inventory the compiler's public API at every effective stability minimum.

Rustdoc resolves macro modules, cfgs, reexports and associated members for us.
A disappearance records the effective (possibly inherited) level; RESERVED
must expose no API. IDs are local to a rustdoc invocation, so compare paths.
"""
import argparse
import json
from pathlib import Path

LEVELS = ("ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON", "RESERVED")


def inventory(document):
    index = document["index"]
    root = str(document["root"])
    result = set()

    def visit(identifier, path, ancestors=frozenset(), inherited=False, rename=None):
        identifier = str(identifier)
        if identifier in ancestors or identifier not in index:
            return
        item = index[identifier]
        kind, body = next(iter(item["inner"].items()))
        if identifier != root and not inherited and item["visibility"] != "public":
            return
        if identifier != root:
            name = rename or item.get("name") or (body.get("name") if kind == "use" else None)
            if not name:
                raise ValueError(f"unnamed public {kind} at {'::'.join(path)}")
            path = (*path, name)
            # Distinct constrained impls may expose the same method name.
            # Source positions distinguish those items without comparing the
            # invocation-local rustdoc IDs or printing machine paths.
            span = item.get("span")
            origin = (span["filename"], tuple(span["begin"]), tuple(span["end"])) if span else None
            result.add(("::".join(path), kind, origin))
        ancestors = ancestors | {identifier}
        if kind == "module":
            for child in body["items"]:
                visit(child, path, ancestors)
        elif kind in ("struct", "union", "enum", "trait"):
            if kind == "struct":
                shape = body["kind"]
                if "plain" in shape:
                    children = shape["plain"]["fields"]
                elif "tuple" in shape:
                    children = [field for field in shape["tuple"] if field is not None]
                else:
                    children = []
            else:
                children = body.get("fields", body.get("variants", body.get("items", [])))
            for child in children:
                visit(child, path, ancestors, kind in ("trait", "enum"))
            # Synthetic blanket/auto impls belong to dependencies; inherent
            # methods and explicit local trait implementations are our surface.
            for impl_id in body.get("impls", body.get("implementations", [])):
                implementation = index.get(str(impl_id), {}).get("inner", {}).get("impl", {})
                if implementation.get("is_synthetic") or implementation.get("blanket_impl") is not None:
                    continue
                trait = implementation.get("trait")
                if trait:
                    trait_path = document.get("paths", {}).get(str(trait["id"]), {}).get("path")
                    impl_name = "impl:" + ("::".join(trait_path) if trait_path else trait["path"])
                else:
                    impl_name = "impl:inherent"
                for child in implementation.get("items", []):
                    visit(child, (*path, impl_name), ancestors, trait is not None)
        elif kind == "variant":
            shape = body["kind"]
            children = shape.get("struct", {}).get("fields", []) if isinstance(shape, dict) else []
            if isinstance(shape, dict) and "tuple" in shape:
                children = [field for field in shape["tuple"] if field is not None]
            for child in children:
                visit(child, path, ancestors, True)
        elif kind == "use":
            # Keep the reexport itself even when it resolves outside this crate.
            # Follow local aliases even through private modules, including
            # associated members on reexported types. External targets have
            # no local index entry; their reexport still needs a level.
            target = str(body.get("id"))
            if body.get("is_glob") and target in index:
                target_body = index[target]["inner"].get("module", {})
                for child in target_body.get("items", []):
                    visit(child, path[:-1], ancestors)
            elif target in index:
                visit(target, path[:-1], ancestors, True, path[-1])

    visit(root, ())
    return result


def check(documents):
    surfaces = {level: inventory(documents[level]) for level in LEVELS}
    if not surfaces["ALPHA"]:
        raise ValueError("normal public inventory is empty (canary failed)")
    def names(surface):
        return sorted({(path, kind) for path, kind, _origin in surface})

    if surfaces["RESERVED"]:
        raise ValueError("unmarked public API at RESERVED: " + repr(names(surfaces["RESERVED"])))
    previous = surfaces["ALPHA"]
    recorded = {}
    for lower, higher in zip(LEVELS, LEVELS[1:]):
        current = surfaces[higher]
        if current - previous:
            raise ValueError(f"public API appears only at {higher}: {names(current - previous)}")
        for item in previous - current:
            recorded[item] = lower
        previous = current
    return recorded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="directory containing ALPHA.json through RESERVED.json")
    args = parser.parse_args()
    documents = {level: json.loads((args.directory / f"{level}.json").read_text()) for level in LEVELS}
    for (path, kind, _origin), level in sorted(check(documents).items(), key=lambda entry: repr(entry[0])):
        print(f"{level}\t{kind}\t{path}")


if __name__ == "__main__":
    main()
