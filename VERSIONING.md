# RouteWarden TCP Warden Versioning & Release Guide

This document describes versioning policies for **RouteWarden TCP Warden** (`github.com/routewarden/tcp-warden`).

## 1. Single Source of Truth (`version.json`)

The canonical version of TCP Warden is stored in [`version.json`](version.json) at the repository root:

```json
{
  "version": "v1.0.6"
}
```

## 2. Semantic Versioning Specification

RouteWarden follows standard [Semantic Versioning (SemVer 2.0.0)](https://semver.org/):

$$\text{v}\mathbf{MAJOR}.\mathbf{MINOR}.\mathbf{PATCH}$$

- **MAJOR** (`v2.0.0`): Breaking architectural changes, protocol syntax redesigns, or incompatible configuration schemas.
- **MINOR** (`v1.1.0`): Backwards-compatible features (e.g. new protocol inspectors, new bouncers, new metrics).
- **PATCH** (`v1.0.1`): Bug fixes, memory optimizations, or documentation improvements.

## 3. Version Update Script (`scripts/update-version.sh`)

To update and synchronize the version across all codebase files, use the provided helper script:

```bash
# Update version and sync files:
./scripts/update-version.sh v1.1.0

# Or re-synchronize using the current version in version.json:
./scripts/update-version.sh
```

This automatically synchronizes:
- [`version.json`](version.json)
- [`main.go`](main.go) (`version = "X.Y.Z"`)
- [`Dockerfile`](Dockerfile) (`ARG VERSION=X.Y.Z`)
- Documentation API references
- Verified by unit test `TestVersionMatchesJSON` in `main_test.go`

