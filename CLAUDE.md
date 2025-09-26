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
- **Output Options**:
  - `--format number` (default): Outputs just the net source size in bytes
  - `--format csv`: Outputs `image_url,size_in_bytes` format
  - `--append FILE`: Appends output to specified file instead of stdout
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

## SBOM-Based Base/Builder Image Detection

### Overview
The script analyzes SPDX SBOMs to identify base and builder images, then performs blob-level deduplication to calculate net source container sizes.

### SBOM Discovery
- **SBOM Tag Format**: `sha256-<manifest-digest>.sbom`
- **Supports**: Both single-arch and multi-arch (image-index) containers
- **Multi-arch Strategy**: For image indexes, analyzes individual architecture SBOMs via `VARIANT_OF` relationships

### Relationship Analysis
The script looks for specific SPDX relationship types:

1. **DESCENDANT_OF**: Target image is descendant of base image
   - Example: `yq-container` → `ubi9/ubi` (base image)

2. **BUILD_TOOL_OF**: Builder image used to construct target
   - Example: `git-clone` → `yq-container` (builder image)

### Target Element Identification
Multi-strategy approach to find the correct target container in SBOMs:

1. **Primary Strategy**: Find elements that are subjects of `DESCENDANT_OF` relationships
2. **App Detection**: Prefer elements containing keywords: "yq", "app", "main", "service"
3. **DESCRIBES Fallback**: Use document `DESCRIBES` relationships
4. **Package Fallback**: Search packages with OCI/Docker references

### Blob-Level Deduplication
Instead of simple size subtraction, the script:

1. **Extracts Blob Details**: Gets digest, size, and media type for each blob
2. **Collects Parent Blobs**: Gathers all blobs from base/builder source containers
3. **Deduplication Logic**: Only counts child blobs that don't match any parent blob digest
4. **Net Size Calculation**: Sums sizes of unique blobs only

### purl Parsing
Extracts container image references from SPDX external references:
- **Format**: `pkg:oci/name@version?repository_url=registry.io/repo`
- **Key Feature**: Uses `repository_url` query parameter for actual registry location
- **Supports**: Both digest-based (`@sha256:...`) and tag-based (`:tag`) references

## Usage Examples

### Command Line Options
```bash
# Basic usage - outputs size in bytes to stdout
./measure-source-size.py registry.redhat.io/ubi8:latest

# Read image URL from stdin
echo "registry.redhat.io/ubi8:latest" | ./measure-source-size.py

# CSV format - outputs image,size
./measure-source-size.py --format csv registry.redhat.io/ubi8:latest

# Append to file instead of stdout
./measure-source-size.py --append measurements.csv registry.redhat.io/ubi8:latest

# CSV format appended to file
./measure-source-size.py --format csv --append results.csv registry.redhat.io/ubi8:latest

# Verbose output with JSON details
./measure-source-size.py -v -j registry.redhat.io/ubi8:latest
```

### Batch Processing
```bash
# Measure multiple images and append to CSV file
for image in image1:latest image2:v1.0 image3:stable; do
    ./measure-source-size.py --format csv --append batch_results.csv "$image"
done

# Using stdin for batch processing from a file
cat image_list.txt | while read image; do
    echo "$image" | ./measure-source-size.py --format csv --append batch_results.csv
done

# Pipeline processing
cat image_list.txt | xargs -I {} ./measure-source-size.py --format csv --append results.csv {}
```

## Real-World Examples

### Multi-arch Image (Image Index)
- **Input**: `quay.io/.../yq:build-image-index`
- **Process**: Finds unified + per-arch source containers, analyzes image-index SBOM
- **Result**: 164 unique blobs (1.09GB) after deduplicating 4 shared blobs (319MB)

### Single-arch Image
- **Input**: `quay.io/.../yq@sha256:333a3e...`
- **Process**: Finds source container, analyzes arch-specific SBOM
- **Result**: 2 unique blobs (10.3MB) after deduplicating 1 shared blob (77MB)

### Red Hat Registry (registry.redhat.io)
- Uses Bearer token authentication
- Supports both unified and per-architecture source containers
- Example: `ubi8:latest` → 5 source containers (299MB total)

### Quay.io
- Public images work with anonymous access
- Uses digest-based method when tag-based fails
- Complex multi-arch images with extensive base/builder hierarchies

## Key Method Details

### Blob Processing
- `extract_manifest_blobs()`: Extracts individual blob information from manifests
- `deduplicate_child_blobs()`: Compares child vs parent blobs by digest
- Returns detailed blob analysis with duplicate/unique counts

### SBOM Processing
- `get_sbom_tag()`: Constructs SBOM tag from manifest digest
- `parse_spdx_for_base_images()`: Main SBOM analysis entry point
- `_find_target_element_in_sbom()`: Smart target container identification
- `_extract_image_from_element()`: Extracts pullable image references from SPDX elements

### Enhanced Error Handling
- **Target Misidentification**: Robust fallback strategies for target element detection
- **SBOM Variations**: Handles both image-index and architecture-specific SBOMs
- **Blob Analysis**: Graceful handling of missing or malformed blob information
- **Authentication**: Comprehensive registry access with multiple credential sources

## Development Notes
- Built for defensive security analysis
- Follows OCI registry API standards
- Compatible with Docker, Podman, and Skopeo credential storage
- Designed for automation and scripting integration
- **Blob-aware**: Provides accurate deduplication at the layer level
- **SBOM-native**: Leverages container build provenance for intelligent analysis