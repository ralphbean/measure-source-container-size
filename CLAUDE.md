# measure-source-size.py - AI Assistant Documentation

## Overview
A Python script that measures the size of source containers associated with OCI artifacts. Source containers contain the source code used to build regular container images.

## How It Works

### Source Container Discovery
The script uses two algorithms to find source containers:

1. **Tag-based method**: Appends `-source` suffix to tags
   - `latest` → `latest-source`
   - `v1.2.3` → `v1.2.3-source`

2. **Digest-based method**: Uses manifest digest to create source tag
   - Get manifest digest (e.g., `sha256:abc123...`)
   - Convert to `sha256-abc123....src` format

### Authentication
- Uses OAuth 2.0 Bearer token authentication
- Loads credentials from standard Docker/Podman config locations:
  - `~/.docker/config.json`
  - `/var/run/containers/0/auth.json` (Podman rootless)
  - `/run/containers/0/auth.json` (Podman rootful)
  - `$XDG_RUNTIME_DIR/containers/auth.json` (Podman XDG)
- Falls back to anonymous access if authentication fails
- No Basic authentication (removed for security)

### Image Type Support
- **Single images**: Tries both algorithms sequentially
- **Image indexes/manifest lists**:
  - Checks for unified source container (both algorithms)
  - Checks each architecture source container (both algorithms)

### Output Format
- **stdout**: Total size in bytes (for scripting)
- **stderr**: All other information (verbose logs, container details)
- Proper OCI URL syntax:
  - Tags: `registry/repo:tag`
  - Digests: `registry/repo@sha256:digest`

## Architecture Details

### Key Methods
- `get_source_container_tag()`: Algorithm 1 (tag-based)
- `get_digest_based_source_tag()`: Algorithm 2 (digest-based)
- `_get_bearer_token()`: OAuth 2.0 token acquisition
- `make_registry_request()`: Authenticated HTTP requests with fallback
- `find_source_containers()`: Main discovery logic

### Error Handling
- Graceful authentication failure handling
- Anonymous access retry for public registries
- 404 handling for missing source containers
- Comprehensive logging in verbose mode

## Real-World Examples

### Red Hat Registry (registry.redhat.io)
- Uses Bearer token authentication
- Supports both unified and per-architecture source containers
- Example: `ubi8:latest` → 5 source containers (299MB total)

### Quay.io
- Public images work with anonymous access
- Uses digest-based method when tag-based fails
- Example: Complex multi-arch image → 1.3GB of source containers

## Development Notes
- Built for defensive security analysis
- Follows OCI registry API standards
- Compatible with Docker, Podman, and Skopeo credential storage
- Designed for automation and scripting integration