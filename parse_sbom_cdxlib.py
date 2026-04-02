#!/usr/bin/env python3
"""
CycloneDX SBOM Parser — using cyclonedx-python-lib
Same output goal as parse_sbom.py but using the official library
instead of raw JSON parsing.
"""

import json
import sys
from collections import defaultdict

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich import box

console = Console()


# ── helpers ────────────────────────────────────────────────────────────
def _prop(comp: Component, key: str) -> str | None:
    """Return the first matching property value."""
    for p in comp.properties:
        if p.name == key:
            return p.value
    return None


def _id_types(comp: Component) -> list[str]:
    """Return list of identifier type names present on a component."""
    ids = []
    if comp.purl:
        ids.append("PURL")
    if comp.cpe:
        ids.append("CPE")
    if comp.swid:
        ids.append("SWID")
    if comp.hashes:
        for h in comp.hashes:
            algo = h.alg.name.replace("_", "-")
            if algo not in ids:
                ids.append(algo)
    if comp.omnibor_ids:
        ids.append("OmniBOR")
    if comp.swhids:
        ids.append("SWHID")
    return ids


def _id_values(comp: Component) -> dict[str, str]:
    """Return a mapping of identifier type → actual value string."""
    vals: dict[str, str] = {}
    if comp.purl:
        vals["PURL"] = str(comp.purl)
    if comp.cpe:
        vals["CPE"] = comp.cpe
    if comp.swid:
        vals["SWID"] = f"{comp.swid.tag_id}"
    if comp.hashes:
        for h in comp.hashes:
            algo = h.alg.name.replace("_", "-")
            vals[algo] = h.value
    if comp.omnibor_ids:
        vals["OmniBOR"] = ", ".join(str(o) for o in comp.omnibor_ids)
    if comp.swhids:
        vals["SWHID"] = ", ".join(str(s) for s in comp.swhids)
    return vals


def _short_layer(sha: str) -> str:
    if sha.startswith("sha256:"):
        return f"sha256:{sha[7:19]}…"
    return sha[:20] + "…"


# ── load ───────────────────────────────────────────────────────────────
def load_sbom(path: str) -> Bom:
    with open(path, "r") as f:
        data = json.load(f)
    return Bom.from_json(data=data)


# ── metadata ───────────────────────────────────────────────────────────
def print_metadata(bom: Bom) -> None:
    meta = bom.metadata
    comp = meta.component

    tools = []
    if meta.tools and hasattr(meta.tools, "components"):
        tools = [f"{t.name} {t.version}" for t in meta.tools.components]

    table = Table(
        title="📦 SBOM Metadata (via cyclonedx-python-lib)",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold cyan",
    )
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Format", f"CycloneDX {bom.version}")
    table.add_row("Serial", str(bom.serial_number) if bom.serial_number else "—")
    table.add_row("Timestamp", str(meta.timestamp) if meta.timestamp else "—")
    table.add_row("Tool", ", ".join(tools) or "—")
    if comp:
        table.add_row("Subject", f"{comp.name}  ({comp.type.name})")
        table.add_row("Version / Digest", comp.version or "—")
    console.print(table)
    console.print()


# ── layer map ──────────────────────────────────────────────────────────
def build_layer_map(bom: Bom):
    """Same logic as parse_sbom.py but via the library's Component model."""
    all_layers: list[str] = []
    layer_set: set[str] = set()
    layer_eco_map: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    layer_refs: dict[str, dict[str, int]] = defaultdict(
        lambda: {"primary": 0, "secondary": 0}
    )
    layer_positions: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    layer_pos0_paths: dict[str, set] = defaultdict(set)
    no_layer: dict[str, list] = defaultdict(list)

    for comp in bom.components:
        ecosystem = _prop(comp, "syft:package:type") or comp.type.name.lower()

        # skip file-level components — too noisy for layer analysis
        if ecosystem == "file":
            continue

        info = {
            "name": comp.name,
            "version": comp.version or "",
            "ids": _id_types(comp),
            "id_values": _id_values(comp),
            "bom_ref": str(comp.bom_ref),
        }

        comp_layers: set[str] = set()
        primary_layer = None
        loc_layers: dict[int, str] = {}
        loc_paths: dict[int, str] = {}

        for p in comp.properties:
            if ":layerID" in p.name:
                parts = p.name.split(":")
                pos = int(parts[2])
                layer_sha = p.value
                loc_layers[pos] = layer_sha
                if layer_sha not in layer_set:
                    all_layers.append(layer_sha)
                    layer_set.add(layer_sha)
                if pos == 0:
                    primary_layer = layer_sha
                layer_positions[layer_sha][pos] += 1
                comp_layers.add(layer_sha)
            elif ":path" in p.name and ":layerID" not in p.name:
                parts = p.name.split(":")
                pos = int(parts[2])
                loc_paths[pos] = p.value

        if 0 in loc_layers and 0 in loc_paths:
            layer_pos0_paths[loc_layers[0]].add(loc_paths[0])

        if primary_layer:
            layer_eco_map[primary_layer][ecosystem].append(info)
            layer_refs[primary_layer]["primary"] += 1
            for sha in comp_layers:
                if sha != primary_layer:
                    layer_refs[sha]["secondary"] += 1
        elif comp_layers:
            first = next(iter(comp_layers))
            layer_refs[first]["secondary"] += 1
            for sha in comp_layers - {first}:
                layer_refs[sha]["secondary"] += 1
        else:
            no_layer[ecosystem].append(info)

    pos0_unique = {sha: len(paths) for sha, paths in layer_pos0_paths.items()}
    return all_layers, layer_eco_map, layer_refs, layer_positions, pos0_unique, no_layer


def sort_layers(
    all_layers: list[str],
    layer_positions: dict[str, dict[int, int]],
    pos0_unique: dict[str, int],
) -> list[str]:
    """Estimate bottom→top stacking via position-index heuristic."""

    def _key(sha: str):
        pos = layer_positions.get(sha, {})
        if not pos:
            return (1, 0.0)
        if 0 not in pos:
            total = sum(pos.values())
            avg = sum(p * c for p, c in pos.items()) / total
            return (0, -avg)
        pos0_count = pos.get(0, 1)
        unique = pos0_unique.get(sha, pos0_count)
        return (1, unique / pos0_count)

    return sorted(all_layers, key=_key)


# ── dependencies ───────────────────────────────────────────────────────
def build_dep_index(bom: Bom) -> dict[str, int]:
    """bom_ref → number of direct dependencies."""
    idx: dict[str, int] = {}
    for dep in bom.dependencies:
        if dep.dependencies:
            idx[str(dep.ref)] = len(dep.dependencies)
    return idx


def print_dependencies(bom: Bom) -> None:
    # 1. Map bom-refs to component info
    ref_to_comp = {}
    for c in bom.components:
        eco = _prop(c, "syft:package:type") or c.type.name.lower()
        ref_to_comp[str(c.bom_ref)] = {"name": c.name, "version": c.version, "eco": eco}

    # 2. Build graph and find roots
    graph = defaultdict(list)
    has_parent = set()

    for dep in bom.dependencies:
        parent_ref = str(dep.ref)
        if hasattr(dep, "dependencies") and dep.dependencies:
            for child in dep.dependencies:
                child_ref = str(child.ref)
                graph[parent_ref].append(child_ref)
                has_parent.add(child_ref)

    if not graph:
        return

    # A "root" is a node that has children but is never a child itself
    roots = [r for r in graph if r not in has_parent]

    if not roots:
        # Avoid infinite recursion if there are cyclical deps but no true roots
        console.print(
            "[yellow]Dependency graph exists but has no clear roots (cycles detected).[/]"
        )
        return

    # Group roots by ecosystem for cleaner display
    roots_by_eco = defaultdict(list)
    for r in roots:
        comp = ref_to_comp.get(r)
        eco = comp["eco"] if comp else "unknown"
        roots_by_eco[eco].append(r)

    console.rule("[bold green]🌳  Package Dependency Trees", style="green")
    console.print()

    def _add_children(node: Tree, ref: str, visited: set):
        for child_ref in sorted(
            graph.get(ref, []),
            key=lambda r: ref_to_comp.get(r, {}).get("name", r).lower(),
        ):
            child_comp = ref_to_comp.get(child_ref)
            if not child_comp:
                node.add(f"[dim]{child_ref}[/]")
                continue

            label = f"[white]{child_comp['name']}[/] [dim]{child_comp['version']}[/]"

            if child_ref in visited:
                node.add(f"{label} [dim italic](already listed)[/]")
            else:
                branch = node.add(label)
                visited.add(child_ref)
                _add_children(branch, child_ref, visited)

    for eco in sorted(roots_by_eco):
        eco_roots = roots_by_eco[eco]
        # Sort roots alphabetically by component name
        eco_roots.sort(key=lambda r: ref_to_comp.get(r, {}).get("name", r).lower())

        console.print(f"[bold green]{eco}[/]")
        for root_ref in eco_roots:
            comp = ref_to_comp.get(root_ref)
            label = (
                f"[bold white]{comp['name']}[/] [green]{comp['version']}[/]"
                if comp
                else f"[bold]{root_ref}[/]"
            )
            tree = Tree(label, guide_style="dim")
            _add_children(tree, root_ref, {root_ref})
            console.print(tree)
        console.print()


# ── render ─────────────────────────────────────────────────────────────
def render(bom: Bom, show_deps: bool = False) -> None:
    print_metadata(bom)

    all_layers, layer_eco_map, layer_refs, layer_positions, pos0_unique, no_layer = (
        build_layer_map(bom)
    )
    dep_idx = build_dep_index(bom)

    if all_layers:
        sorted_layers = sort_layers(all_layers, layer_positions, pos0_unique)
        n = len(sorted_layers)

        console.rule(
            "[bold magenta]🐳 Image Layers  [dim](estimated stacking: bottom → top)[/]",
            style="magenta",
        )
        console.print()

        for i, layer_sha in enumerate(sorted_layers, 1):
            eco_map = layer_eco_map.get(layer_sha, {})
            total = sum(len(v) for v in eco_map.values())
            refs = layer_refs[layer_sha]

            pos_label = "BOTTOM" if i == 1 else ("TOP" if i == n else f"{i}/{n}")

            ref_parts = []
            if refs["primary"]:
                ref_parts.append(f"{refs['primary']} primary")
            if refs["secondary"]:
                ref_parts.append(f"{refs['secondary']} secondary")
            ref_str = ", ".join(ref_parts) or "no refs"

            console.print(
                f"[bold bright_cyan]Layer {i}[/]  "
                f"[dim]{_short_layer(layer_sha)}[/]  "
                f"[bold magenta][{pos_label}][/]  "
                f"[dim italic]({ref_str} refs)[/]"
            )

            if eco_map:
                # discover all identifier types in this layer
                all_id_types: set[str] = set()
                for comps in eco_map.values():
                    for c in comps:
                        all_id_types.update(c["ids"])
                id_type_list = sorted(all_id_types) if all_id_types else []

                # count per-ecosystem per-id-type
                layer_totals = {t: 0 for t in id_type_list}
                layer_totals["None"] = 0

                table = Table(box=box.SIMPLE_HEAVY, padding=(0, 1), show_lines=False)
                table.add_column("Ecosystem", style="bold green", min_width=16)
                table.add_column("Packages", justify="right", style="bright_white")
                for t in id_type_list:
                    table.add_column(t, justify="right", style="yellow")
                table.add_column("No ID", justify="right", style="dim")

                for eco in sorted(eco_map, key=lambda e: -len(eco_map[e])):
                    comps = eco_map[eco]
                    row = [eco, str(len(comps))]
                    has_any_count = 0
                    for t in id_type_list:
                        cnt = sum(1 for c in comps if t in c["ids"])
                        layer_totals[t] += cnt
                        row.append(str(cnt))
                        has_any_count += cnt
                    # "No ID" = components with empty ids list
                    no_id = sum(1 for c in comps if not c["ids"])
                    layer_totals["None"] += no_id
                    row.append(str(no_id))
                    table.add_row(*row)

                if len(eco_map) > 1:
                    total_row = ["[bold]TOTAL[/]", f"[bold]{total}[/]"]
                    for t in id_type_list:
                        total_row.append(str(layer_totals[t]))
                    total_row.append(str(layer_totals["None"]))
                    table.add_row(*total_row, style="on grey23")
                console.print(table)

                # per-ecosystem detail: individual packages
                for eco in sorted(eco_map, key=lambda e: -len(eco_map[e])):
                    comps = eco_map[eco]

                    # discover which id types have actual values in this ecosystem
                    eco_id_types: list[str] = []
                    seen = set()
                    for c in comps:
                        for t in c["ids"]:
                            if t not in seen:
                                eco_id_types.append(t)
                                seen.add(t)

                    detail = Table(
                        title=f"{eco}",
                        box=box.SIMPLE,
                        padding=(0, 1),
                        show_lines=False,
                        title_style="bold green",
                        title_justify="left",
                        expand=True,
                    )
                    detail.add_column("#", style="dim", width=4, justify="right")
                    detail.add_column("Package", style="bold white", no_wrap=True)
                    detail.add_column("Version", style="green", no_wrap=True)
                    for t in eco_id_types:
                        detail.add_column(t, style="yellow", overflow="fold")

                    for idx, c in enumerate(
                        sorted(comps, key=lambda x: x["name"].lower()), 1
                    ):
                        row = [str(idx), c["name"], c["version"]]
                        for t in eco_id_types:
                            val = c["id_values"].get(t, "")
                            row.append("[dim]—[/]" if not val else val)
                        detail.add_row(*row)
                    console.print(detail)
            else:
                console.print(
                    "  [dim]No primary components — only referenced as "
                    "secondary location by components in other layers[/]"
                )
            console.print()
    else:
        console.print("[yellow]No image layer information found.[/]")
        console.print()

    # components without a layer
    if no_layer:
        console.rule("[bold yellow]📁  Components Without Layer Info", style="yellow")
        console.print()

        # Ecosystem summary table
        table = Table(box=box.SIMPLE_HEAVY, padding=(0, 1), show_lines=False)
        table.add_column("Ecosystem", style="bold green", min_width=20)
        table.add_column("Packages", justify="right", style="bright_white")
        for eco in sorted(no_layer, key=lambda e: -len(no_layer[e])):
            table.add_row(eco, str(len(no_layer[eco])))
        console.print(table)
        console.print()

        # Per-ecosystem detail tables
        for eco in sorted(no_layer, key=lambda e: -len(no_layer[e])):
            comps = no_layer[eco]

            eco_id_types: list[str] = []
            seen = set()
            for c in comps:
                for t in c["ids"]:
                    if t not in seen:
                        eco_id_types.append(t)
                        seen.add(t)

            detail = Table(
                title=f"{eco}",
                box=box.SIMPLE,
                padding=(0, 1),
                show_lines=False,
                title_style="bold green",
                title_justify="left",
                expand=True,
            )
            detail.add_column("#", style="dim", width=4, justify="right")
            detail.add_column("Package", style="bold white", no_wrap=True)
            detail.add_column("Version", style="green", no_wrap=True)
            for t in eco_id_types:
                detail.add_column(t, style="yellow", overflow="fold")

            for idx, c in enumerate(sorted(comps, key=lambda x: x["name"].lower()), 1):
                row = [str(idx), c["name"], c["version"]]
                for t in eco_id_types:
                    val = c["id_values"].get(t, "")
                    row.append("[dim]—[/]" if not val else val)
                detail.add_row(*row)

            console.print(detail)

    # ── summary ────────────────────────────────────────────────────
    all_comps = list(bom.components)
    eco_counts: dict[str, int] = defaultdict(int)
    id_counts: dict[str, int] = defaultdict(int)
    no_id_count = 0

    for c in all_comps:
        eco = _prop(c, "syft:package:type") or c.type.name.lower()
        eco_counts[eco] += 1
        ids = _id_types(c)
        if ids:
            for id_type in ids:
                id_counts[id_type] += 1
        else:
            no_id_count += 1

    console.rule("[bold cyan]📊  Summary", style="cyan")
    console.print()

    sum_table = Table(title="Ecosystem Breakdown", box=box.ROUNDED, title_style="bold")
    sum_table.add_column("Ecosystem", style="bold green")
    sum_table.add_column("Count", justify="right", style="bright_white")
    for eco, cnt in sorted(eco_counts.items(), key=lambda x: -x[1]):
        sum_table.add_row(eco, str(cnt))
    sum_table.add_row("[bold]TOTAL[/]", f"[bold]{len(all_comps)}[/]", style="on grey23")
    console.print(sum_table)
    console.print()

    id_table = Table(title="Identifier Coverage", box=box.ROUNDED, title_style="bold")
    id_table.add_column("Identifier Type", style="bold yellow")
    id_table.add_column("Components", justify="right", style="bright_white")
    id_table.add_column("% of Total", justify="right", style="dim")
    for id_type, cnt in sorted(id_counts.items(), key=lambda x: -x[1]):
        pct = f"{cnt / len(all_comps) * 100:.1f}%"
        id_table.add_row(id_type, str(cnt), pct)
    if no_id_count:
        pct = f"{no_id_count / len(all_comps) * 100:.1f}%"
        id_table.add_row("[dim]None[/]", str(no_id_count), pct)
    console.print(id_table)
    console.print()

    if all_layers:
        console.print(f"  [bold]Image layers:[/] {len(all_layers)}")
    dep_count = len(dep_idx)
    console.print(f"  [bold]Components with explicit dependencies:[/] {dep_count}")
    console.print()

    # ── dependency tree ────────────────────────────────────────────────
    if show_deps:
        print_dependencies(bom)


# ── entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    args = sys.argv[1:]
    show_deps = "--show-deps" in args
    if show_deps:
        args.remove("--show-deps")

    path = args[0] if args else "insecure-app-image-sbom-cyclonedx.json"
    console.print(f"\n[dim]Loading {path} via cyclonedx-python-lib …[/]\n")
    bom = load_sbom(path)
    render(bom, show_deps=show_deps)
