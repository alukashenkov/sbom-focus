# Container Image Layer Analysis from CycloneDX SBOMs

Strategy for inferring Docker image layer stacking order from Syft-generated CycloneDX SBOMs, where no explicit layer ordering exists.

## The Problem

CycloneDX has no concept of container image layers. Syft encodes layer information as **vendor-specific properties** on each component:

```json
{
  "name": "syft:location:0:layerID",
  "value": "sha256:95e8890b4a8c..."
},
{
  "name": "syft:location:0:path",
  "value": "/var/lib/dpkg/status"
},
{
  "name": "syft:location:1:layerID",
  "value": "sha256:27d9a8093fcd..."
},
{
  "name": "syft:location:1:path",
  "value": "/usr/share/doc/apt/copyright"
}
```

A single component can reference **multiple layers** across its location entries. The position index (`0`, `1`, `2`, …) is _not_ the layer order — it's the order in which Syft lists the component's file locations.

## Key Insight: Position 0 Semantics

| Position | Meaning | Example |
|----------|---------|---------|
| `location:0` | **Primary discovery file** — where Syft's cataloger first identified the component | `/var/lib/dpkg/status` for debs, `.dist-info/METADATA` for Python |
| `location:1+` | **Additional files** belonging to the same component | Copyright files, conffiles, scripts, shared libs |

> [!IMPORTANT]
> The primary discovery file (pos 0) lives in the **last layer that wrote it**, not the layer where the package was originally installed. For deb packages, all 108 components share `/var/lib/dpkg/status` as their pos-0 path — this file exists in whichever layer last ran `dpkg`.

## The Two-Tier Sorting Heuristic

### Tier 0: Secondary-Only Layers (base/bottom)

Layers that are **never** referenced at position 0. They contain only "installed files" (docs, scripts, binaries) that were discovered via a registry file in another layer.

**Sort key:** Average position index (descending). Higher average = earlier/lower layer.

```
sha256:f58e59cc… → positions {1:3, 2:3, 3:3, …}  → avg ≈ 3.7 → BOTTOM
sha256:27d9a809… → positions {1:79, 2:78, 3:39, …} → avg ≈ 3.3 → 2nd
```

### Tier 1: Primary Layers (upper)

Layers that appear at position 0. They hold discovery/registry files.

**Sort key:** Unique-path ratio = `unique_pos0_paths / total_pos0_refs`

| Layer | Pos-0 refs | Unique pos-0 paths | Ratio | Interpretation |
|-------|:---:|:---:|:---:|---|
| `sha256:95e8890b…` (deb) | 108 | 1 (`/var/lib/dpkg/status`) | **0.009** | Shared registry → lower |
| `sha256:27fee45b…` (python runtime) | 34 | 34 (individual METADATA files) | **1.0** | Per-package discovery → upper |
| `sha256:1e03b1c0…` (app python) | 16 | 16 (individual METADATA files) | **1.0** | Per-package discovery → upper |

> [!NOTE]
> When multiple layers have the same ratio (e.g., both Python layers have ratio 1.0), they sort by natural iteration order from the component list. This typically preserves Syft's cataloger order, which happens to place the runtime layer before the app layer. For more precise ordering among same-ratio layers, additional heuristics would be needed (e.g., dependency depth analysis).

## Result: Reconstructed Stacking Order

```
BOTTOM  sha256:f58e59cc…  — base config files (ca-certs, netbase, openssl)
  2/5   sha256:27d9a809…  — core Debian package files (apt, base-files, bash, …)
  3/5   sha256:95e8890b…  — dpkg status registry (108 deb packages discovered here)
  4/5   sha256:27fee45b…  — Python 3.9 runtime (pip, setuptools + PE binaries)
  TOP   sha256:1e03b1c0…  — Application dependencies (Flask, requests, etc.)
```

## Implementation

```python
def sort_layers_by_stacking(all_layers, layer_positions, pos0_unique_paths):
    def _key(sha):
        pos = layer_positions.get(sha, {})
        if not pos:
            return (1, 0.0)

        # Tier 0: never at position 0 → base layer
        if 0 not in pos:
            total = sum(pos.values())
            avg = sum(p * c for p, c in pos.items()) / total
            return (0, -avg)  # higher avg → sorted first (bottom)

        # Tier 1: has pos-0 refs → sort by unique-path ratio
        pos0_count = pos.get(0, 1)
        unique = pos0_unique_paths.get(sha, pos0_count)
        return (1, unique / pos0_count)  # lower ratio → sorted first (lower)

    return sorted(all_layers, key=_key)
```

## Limitations

- **Heuristic, not definitive.** The SBOM doesn't contain the actual `docker history` layer order. This strategy works well for Syft-generated SBOMs of typical Debian/Ubuntu + Python images but may need adjustment for other base images or package managers.
- **Same-ratio ties.** Layers with identical unique-path ratios (e.g., two Python `pip install` layers) are not distinguished by this heuristic alone.
- **Non-Syft SBOMs.** Other tools (Trivy, Grype) use different property naming conventions. The `syft:location:N:layerID` pattern is Syft-specific.
- **Distroless / scratch images.** Images without a package manager won't have the "shared registry" pattern that this heuristic relies on.
