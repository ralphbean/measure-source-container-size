#!/usr/bin/env python3
"""
Script to measure the size of source containers associated with OCI artifacts.
Source containers typically use a '-source' tag suffix.
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError


class SourceContainerMeasurer:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.auth_config = self._load_docker_config()

    def log(self, message: str):
        if self.verbose:
            print(f"[INFO] {message}", file=sys.stderr)

    def _load_docker_config(self) -> Dict:
        """Load Docker authentication configuration from standard locations."""
        config_paths = [
            Path.home() / ".docker" / "config.json",
            Path("/var/run/containers/0/auth.json"),  # Podman rootless
            Path("/run/containers/0/auth.json"),      # Podman rootful
        ]

        # Also check XDG_RUNTIME_DIR for podman
        xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
        if xdg_runtime:
            config_paths.append(Path(xdg_runtime) / "containers" / "auth.json")

        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path) as f:
                        config = json.load(f)
                        self.log(f"Loaded auth config from {config_path}")
                        return config
                except (json.JSONDecodeError, IOError) as e:
                    self.log(f"Failed to load config from {config_path}: {e}")
                    continue

        self.log("No authentication config found")
        return {}

    def _get_auth_credentials(self, registry: str) -> Optional[Tuple[str, str]]:
        """Get username/password credentials for a registry."""
        if not self.auth_config:
            return None

        auths = self.auth_config.get("auths", {})

        # Try exact match first
        if registry in auths:
            auth_data = auths[registry]
        else:
            # Try with https:// prefix
            registry_with_https = f"https://{registry}"
            if registry_with_https in auths:
                auth_data = auths[registry_with_https]
            else:
                return None

        if "auth" in auth_data:
            # Direct base64 encoded auth - decode it
            try:
                decoded = base64.b64decode(auth_data['auth']).decode()
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
                    return username, password
            except Exception:
                pass
        elif "username" in auth_data and "password" in auth_data:
            # Username/password pair
            return auth_data['username'], auth_data['password']

        return None

    def _parse_www_authenticate(self, www_auth_header: str) -> Optional[Dict[str, str]]:
        """Parse WWW-Authenticate header for Bearer token info."""
        if not www_auth_header.startswith('Bearer '):
            return None

        # Parse Bearer parameters
        params = {}
        bearer_part = www_auth_header[7:]  # Remove 'Bearer '

        # Simple parsing of key=value pairs (with quoted values)
        for part in bearer_part.split(','):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"')
                params[key] = value

        return params

    def _get_bearer_token(self, registry: str, repository: str, scope: str = "pull") -> Optional[str]:
        """Get Bearer token for registry access."""
        # First try to get a manifest to trigger WWW-Authenticate
        test_url = f"https://{registry}/v2/{repository}/manifests/latest"
        req = urllib.request.Request(test_url)

        try:
            with urllib.request.urlopen(req) as response:
                # If we get here without auth, the registry allows anonymous access
                return None
        except HTTPError as e:
            if e.code != 401:
                return None

            www_auth = e.headers.get('WWW-Authenticate')
            if not www_auth:
                return None

            auth_params = self._parse_www_authenticate(www_auth)
            if not auth_params or 'realm' not in auth_params:
                return None

            # Get credentials for token request
            credentials = self._get_auth_credentials(registry)

            # Build token request URL
            token_url = auth_params['realm']
            params = []
            if 'service' in auth_params:
                params.append(f"service={urllib.parse.quote(auth_params['service'])}")

            # Use the provided scope or build it
            if 'scope' in auth_params:
                params.append(f"scope={urllib.parse.quote(auth_params['scope'])}")
            else:
                params.append(f"scope=repository:{repository}:{scope}")

            if params:
                token_url += "?" + "&".join(params)

            self.log(f"Requesting token from: {token_url}")

            # Make token request
            token_req = urllib.request.Request(token_url)
            if credentials:
                username, password = credentials
                credentials_str = f"{username}:{password}"
                encoded = base64.b64encode(credentials_str.encode()).decode()
                token_req.add_header('Authorization', f'Basic {encoded}')

            try:
                with urllib.request.urlopen(token_req) as token_response:
                    token_data = json.loads(token_response.read().decode('utf-8'))
                    token = token_data.get('token') or token_data.get('access_token')
                    if token:
                        self.log(f"Successfully obtained Bearer token for {registry}")
                        return token
            except Exception as e:
                self.log(f"Failed to get Bearer token: {e}")

        return None

    def parse_oci_url(self, url: str) -> Tuple[str, str, str]:
        """Parse OCI URL into registry, repository, and tag/digest."""
        if "://" not in url:
            url = "https://" + url

        parsed = urllib.parse.urlparse(url)
        registry = parsed.netloc
        path = parsed.path.lstrip('/')

        if '@' in path:
            repository, digest = path.rsplit('@', 1)
            tag = None
        elif ':' in path:
            repository, tag = path.rsplit(':', 1)
            digest = None
        else:
            repository = path
            tag = "latest"
            digest = None

        return registry, repository, tag or digest

    def get_source_container_tag(self, original_tag: str) -> str:
        """Generate source container tag from original tag."""
        if original_tag.startswith('sha256:'):
            return original_tag
        return f"{original_tag}-source"

    def get_digest_based_source_tag(self, digest: str) -> str:
        """Generate digest-based source container tag (sha256-digest.src)."""
        if digest.startswith('sha256:'):
            digest_part = digest[7:]  # Remove 'sha256:' prefix
            return f"sha256-{digest_part}.src"
        return digest

    def get_sbom_tag(self, digest: str) -> str:
        """Generate SBOM tag from digest (sha256-digest.sbom)."""
        if digest.startswith('sha256:'):
            digest_part = digest[7:]  # Remove 'sha256:' prefix
            return f"sha256-{digest_part}.sbom"
        return digest

    def make_registry_request(self, url: str, registry: str, repository: str, headers: Dict[str, str] = None) -> Dict:
        """Make authenticated request to registry API."""
        if headers is None:
            headers = {}

        headers.setdefault('Accept', 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json')

        # Try Bearer token authentication
        bearer_token = self._get_bearer_token(registry, repository)
        if bearer_token:
            headers['Authorization'] = f"Bearer {bearer_token}"
            self.log(f"Using Bearer token authentication for {registry}")

        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(req) as response:
                response_text = response.read().decode('utf-8')
                if not response_text.strip():
                    self.log(f"Empty response from {url}")
                    return None
                return json.loads(response_text)
        except json.JSONDecodeError as e:
            self.log(f"JSON decode error for {url}: {e}")
            return None
        except HTTPError as e:
            if e.code == 404:
                return None
            elif e.code == 401:
                self.log(f"Authentication failed for {registry}")
                # Try without authentication if auth failed
                if 'Authorization' in headers:
                    self.log(f"Retrying without authentication for {registry}")
                    del headers['Authorization']
                    req = urllib.request.Request(url, headers=headers)
                    try:
                        with urllib.request.urlopen(req) as response:
                            response_text = response.read().decode('utf-8')
                            if not response_text.strip():
                                self.log(f"Empty response from {url} (retry)")
                                return None
                            return json.loads(response_text)
                    except json.JSONDecodeError as retry_e:
                        self.log(f"JSON decode error for {url} (retry): {retry_e}")
                        return None
                    except HTTPError as retry_e:
                        if retry_e.code == 404:
                            return None
                        self.log(f"Anonymous access also failed for {registry}")
                return None
            raise

    def get_manifest(self, registry: str, repository: str, tag: str) -> Optional[Dict]:
        """Get manifest for a specific tag."""
        url = f"https://{registry}/v2/{repository}/manifests/{tag}"
        self.log(f"Fetching manifest: {url}")
        return self.make_registry_request(url, registry, repository)

    def get_manifest_digest(self, registry: str, repository: str, tag: str) -> Optional[str]:
        """Get the digest of a manifest by making a HEAD request."""
        url = f"https://{registry}/v2/{repository}/manifests/{tag}"
        self.log(f"Fetching manifest digest: {url}")

        headers = {
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json'
        }

        # Try Bearer token authentication
        bearer_token = self._get_bearer_token(registry, repository)
        if bearer_token:
            headers['Authorization'] = f"Bearer {bearer_token}"

        req = urllib.request.Request(url, headers=headers)
        req.get_method = lambda: 'HEAD'

        try:
            with urllib.request.urlopen(req) as response:
                digest = response.headers.get('Docker-Content-Digest')
                if digest:
                    self.log(f"Got manifest digest: {digest}")
                    return digest
        except HTTPError as e:
            if e.code == 404:
                return None
            elif e.code == 401:
                # Try without authentication if auth failed
                if 'Authorization' in headers:
                    self.log(f"Retrying digest request without authentication for {registry}")
                    del headers['Authorization']
                    req = urllib.request.Request(url, headers=headers)
                    req.get_method = lambda: 'HEAD'
                    try:
                        with urllib.request.urlopen(req) as response:
                            digest = response.headers.get('Docker-Content-Digest')
                            if digest:
                                self.log(f"Got manifest digest: {digest}")
                                return digest
                    except HTTPError as retry_e:
                        if retry_e.code == 404:
                            return None
                return None
            raise

        return None

    def get_sbom(self, registry: str, repository: str, tag: str) -> Optional[Dict]:
        """Get SBOM for a specific tag."""
        url = f"https://{registry}/v2/{repository}/manifests/{tag}"
        self.log(f"Fetching SBOM: {url}")

        try:
            # SBOM might be stored as a manifest, so we use the same approach
            sbom_data = self.make_registry_request(url, registry, repository)
            if not sbom_data:
                return None

            # If it's a manifest pointing to a blob, we need to fetch the blob
            if sbom_data.get('mediaType') in ['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json']:
                # Look for SBOM in layers or config
                for layer in sbom_data.get('layers', []):
                    if 'spdx' in layer.get('mediaType', '').lower() or 'sbom' in layer.get('mediaType', '').lower():
                        # Fetch the blob
                        blob_url = f"https://{registry}/v2/{repository}/blobs/{layer['digest']}"
                        blob_data = self.make_registry_request(blob_url, registry, repository)
                        if blob_data:
                            return blob_data

            # Try to parse as direct SBOM data
            return sbom_data
        except Exception as e:
            self.log(f"Error fetching SBOM: {e}")
            return None

    def parse_spdx_for_base_images(self, sbom_data: Dict, target_element_id: str = None, registry: str = None, repository: str = None) -> List[Dict[str, str]]:
        """Parse SPDX SBOM to find base and builder images."""
        if not sbom_data:
            return []

        self.log("Parsing SPDX SBOM for base and builder images")

        found_images = []

        # Get the document creation info to understand the main element
        doc_creation_info = sbom_data.get('creationInfo', {})
        document_name = sbom_data.get('name', '')
        document_namespace = sbom_data.get('documentNamespace', '')

        # If no target element specified, try to find the main container element
        if not target_element_id:
            target_element_id = self._find_target_element_in_sbom(sbom_data)
            if target_element_id:
                self.log(f"Found target container element: {target_element_id}")
            else:
                # Fallback to the old method if the new one fails
                packages = sbom_data.get('packages', [])
                for package in packages:
                    pkg_name = package.get('name', '').lower()
                    external_refs = package.get('externalRefs', [])

                    # Look for the main container being analyzed
                    for ref in external_refs:
                        ref_locator = ref.get('referenceLocator', '')
                        if ref_locator.startswith('pkg:oci/') or ref_locator.startswith('pkg:docker/'):
                            # This might be our target element
                            target_element_id = package.get('SPDXID', '')
                            self.log(f"Found target container element (fallback): {target_element_id}")
                            break
                    if target_element_id:
                        break

        # Look for relationships - focus on DESCENDANT_OF and BUILD_TOOL_OF
        relationships = sbom_data.get('relationships', [])
        self.log(f"Found {len(relationships)} relationships in SBOM")

        for rel in relationships:
            relationship_type = rel.get('relationshipType', '')
            spdx_element_id = rel.get('spdxElementId', '')
            related_element_id = rel.get('relatedSpdxElement', '')

            self.log(f"Relationship: {spdx_element_id} --{relationship_type}--> {related_element_id}")

            # Check if this relationship involves our target element
            is_target_relationship = (
                (target_element_id and spdx_element_id == target_element_id) or
                (not target_element_id)  # If we don't know the target, check all relationships
            )

            if is_target_relationship:
                if relationship_type == 'DESCENDANT_OF':
                    self.log(f"Found DESCENDANT_OF relationship: {spdx_element_id} -> {related_element_id}")
                    # The target is descendant of the related element (base image)
                    base_image = self._extract_image_from_element(sbom_data, related_element_id)
                    if base_image:
                        found_images.append({
                            'type': 'base',
                            'image': base_image,
                            'relationship': 'DESCENDANT_OF'
                        })

            # Check for BUILD_TOOL_OF relationships where the related element is a build tool
            if relationship_type == 'BUILD_TOOL_OF':
                build_target = rel.get('relatedSpdxElement', '')
                builder_element = rel.get('spdxElementId', '')

                # Check if this build tool was used for our target
                is_builder_for_target = (
                    (target_element_id and build_target == target_element_id) or
                    (not target_element_id)  # If we don't know the target, check all
                )

                if is_builder_for_target:
                    self.log(f"Found BUILD_TOOL_OF relationship: {builder_element} -> {build_target}")
                    builder_image = self._extract_image_from_element(sbom_data, builder_element)
                    if builder_image:
                        found_images.append({
                            'type': 'builder',
                            'image': builder_image,
                            'relationship': 'BUILD_TOOL_OF'
                        })

        # If we didn't find any DESCENDANT_OF or BUILD_TOOL_OF relationships,
        # check if this is an image-index SBOM with VARIANT_OF relationships
        if not found_images:
            variant_elements = []
            for rel in relationships:
                if rel.get('relationshipType') == 'VARIANT_OF':
                    variant_element = rel.get('spdxElementId', '')
                    if variant_element:
                        variant_elements.append(variant_element)

            if variant_elements:
                self.log(f"Found image-index SBOM with {len(variant_elements)} variants, checking their SBOMs")
                # For each variant, try to get its digest and check its SBOM
                for variant_element in variant_elements:
                    variant_images = self._check_variant_sbom(sbom_data, variant_element, registry, repository)
                    found_images.extend(variant_images)

        self.log(f"Found {len(found_images)} base/builder images")
        return found_images

    def _check_variant_sbom(self, parent_sbom_data: Dict, variant_element_id: str, registry: str, repository: str) -> List[Dict[str, str]]:
        """Check SBOM of a variant image for base/builder relationships."""
        # Try to get the digest for this variant
        variant_digest = self._get_digest_from_element(parent_sbom_data, variant_element_id)
        if not variant_digest:
            self.log(f"Could not find digest for variant element: {variant_element_id}")
            return []

        self.log(f"Checking SBOM for variant: {variant_element_id} (digest: {variant_digest})")

        try:
            # Generate SBOM tag for this variant
            variant_sbom_tag = self.get_sbom_tag(variant_digest)

            # Fetch the variant's SBOM
            variant_sbom_data = self.get_sbom(registry, repository, variant_sbom_tag)
            if not variant_sbom_data:
                self.log(f"No SBOM found for variant: {variant_sbom_tag}")
                return []

            # Parse this SBOM for base/builder relationships
            variant_target_id = self._find_target_element_in_sbom(variant_sbom_data)
            self.log(f"Variant target element: {variant_target_id}")
            variant_images = self._parse_sbom_relationships(variant_sbom_data, variant_target_id)

            return variant_images

        except Exception as e:
            self.log(f"Error checking variant SBOM: {e}")
            return []

    def _get_digest_from_element(self, sbom_data: Dict, element_id: str) -> Optional[str]:
        """Extract digest from an SPDX element."""
        packages = sbom_data.get('packages', [])
        for package in packages:
            if package.get('SPDXID') == element_id:
                # Look for digest in external references
                external_refs = package.get('externalRefs', [])
                for ref in external_refs:
                    ref_locator = ref.get('referenceLocator', '')
                    if 'sha256:' in ref_locator:
                        # Extract just the digest part
                        if '@sha256:' in ref_locator:
                            digest_part = ref_locator.split('@')[1]
                        elif 'sha256:' in ref_locator:
                            sha_index = ref_locator.find('sha256:')
                            digest_part = ref_locator[sha_index:]
                        else:
                            continue

                        # Remove any query parameters after the digest
                        if '?' in digest_part:
                            digest_part = digest_part.split('?')[0]

                        return digest_part
        return None

    def _find_target_element_in_sbom(self, sbom_data: Dict) -> Optional[str]:
        """Find the main target element in an SBOM."""
        relationships = sbom_data.get('relationships', [])

        # Strategy 1: Look for elements that are DESCENDANT_OF base images
        # These are typically the main application containers we're measuring
        potential_targets = set()
        for rel in relationships:
            if rel.get('relationshipType') == 'DESCENDANT_OF':
                subject_element = rel.get('spdxElementId', '')
                if subject_element.startswith('SPDXRef-image-'):
                    # Filter out builder images
                    if 'git-clone' not in subject_element and 'build' not in subject_element.lower():
                        potential_targets.add(subject_element)

        if potential_targets:
            # If we have multiple candidates, prefer the one that looks most like the application
            for target in potential_targets:
                # Look for elements that contain the application name (yq, etc.)
                if any(app_name in target.lower() for app_name in ['yq', 'app', 'main', 'service']):
                    self.log(f"Selected target element (app-like): {target}")
                    return target
            # Otherwise, just return the first one
            target = list(potential_targets)[0]
            self.log(f"Selected target element (first descendant): {target}")
            return target

        # Strategy 2: Check for DESCRIBES relationships - the document describes the main element
        for rel in relationships:
            if rel.get('relationshipType') == 'DESCRIBES':
                described_element = rel.get('relatedSpdxElement', '')
                if described_element and described_element.startswith('SPDXRef-image-'):
                    # Make sure it's not a builder image (usually has different naming patterns)
                    if 'git-clone' not in described_element and 'build' not in described_element.lower():
                        self.log(f"Selected target element (described): {described_element}")
                        return described_element

        # Strategy 3: Fallback - look for packages with container references that aren't builders
        packages = sbom_data.get('packages', [])
        for package in packages:
            spdx_id = package.get('SPDXID', '')
            if spdx_id.startswith('SPDXRef-image-') and 'git-clone' not in spdx_id and 'build' not in spdx_id.lower():
                external_refs = package.get('externalRefs', [])
                for ref in external_refs:
                    ref_locator = ref.get('referenceLocator', '')
                    if ref_locator.startswith('pkg:oci/') or ref_locator.startswith('pkg:docker/'):
                        self.log(f"Selected target element (fallback): {spdx_id}")
                        return spdx_id
        return None

    def _parse_sbom_relationships(self, sbom_data: Dict, target_element_id: str) -> List[Dict[str, str]]:
        """Parse SBOM relationships for a specific target element."""
        found_images = []
        relationships = sbom_data.get('relationships', [])

        for rel in relationships:
            relationship_type = rel.get('relationshipType', '')
            spdx_element_id = rel.get('spdxElementId', '')
            related_element_id = rel.get('relatedSpdxElement', '')

            self.log(f"Variant relationship: {spdx_element_id} --{relationship_type}--> {related_element_id}")

            # Check if this relationship involves our target element
            is_target_relationship = (
                (target_element_id and spdx_element_id == target_element_id) or
                (not target_element_id)
            )

            if relationship_type in ['DESCENDANT_OF', 'BUILD_TOOL_OF']:
                self.log(f"  Target check: target_element_id={target_element_id}, spdx_element_id={spdx_element_id}, is_target={is_target_relationship}")

            if is_target_relationship:
                if relationship_type == 'DESCENDANT_OF':
                    self.log(f"Found DESCENDANT_OF relationship in variant: {spdx_element_id} -> {related_element_id}")
                    base_image = self._extract_image_from_element(sbom_data, related_element_id)
                    if base_image:
                        found_images.append({
                            'type': 'base',
                            'image': base_image,
                            'relationship': 'DESCENDANT_OF'
                        })

            if relationship_type == 'BUILD_TOOL_OF':
                build_target = rel.get('relatedSpdxElement', '')
                builder_element = rel.get('spdxElementId', '')

                is_builder_for_target = (
                    (target_element_id and build_target == target_element_id) or
                    (not target_element_id)
                )

                if is_builder_for_target:
                    self.log(f"Found BUILD_TOOL_OF relationship in variant: {builder_element} -> {build_target}")
                    builder_image = self._extract_image_from_element(sbom_data, builder_element)
                    if builder_image:
                        found_images.append({
                            'type': 'builder',
                            'image': builder_image,
                            'relationship': 'BUILD_TOOL_OF'
                        })

        return found_images

    def _extract_image_from_element(self, sbom_data: Dict, element_id: str) -> Optional[str]:
        """Extract container image reference from an SPDX element."""
        packages = sbom_data.get('packages', [])

        for package in packages:
            if package.get('SPDXID') == element_id:
                pkg_name = package.get('name', '')
                self.log(f"Extracting image from element {element_id} (name: {pkg_name})")

                # Check download location
                download_location = package.get('downloadLocation', '')
                if download_location and ('docker.io' in download_location or 'registry' in download_location or '/' in download_location):
                    self.log(f"Found image from downloadLocation: {download_location}")
                    return download_location

                # Check external references
                external_refs = package.get('externalRefs', [])
                self.log(f"Found {len(external_refs)} external references for {element_id}")

                for ref in external_refs:
                    ref_type = ref.get('referenceType', '')
                    ref_locator = ref.get('referenceLocator', '')
                    self.log(f"  ExternalRef: type={ref_type}, locator={ref_locator}")

                    # Handle different reference types
                    if ref_type in ['purl', 'container-image', 'package-url'] and ref_locator:
                        if ref_locator.startswith('pkg:docker/') or ref_locator.startswith('pkg:oci/'):
                            self.log(f"Processing container purl: {ref_locator}")
                            image_ref = self._parse_purl_to_image_ref(ref_locator)
                            self.log(f"Parsed image reference: {image_ref}")
                            if image_ref:
                                return image_ref
                        elif ref_locator.startswith('pkg:'):
                            # Try to extract repository URL from purl query parameters
                            self.log(f"Processing generic purl: {ref_locator}")
                            image_ref = self._extract_registry_from_purl(ref_locator)
                            if image_ref:
                                return image_ref

                    # Check for direct registry URLs
                    elif 'registry' in ref_locator or 'quay.io' in ref_locator or 'docker.io' in ref_locator:
                        self.log(f"Found direct registry reference: {ref_locator}")
                        return ref_locator

                # Fallback: check package name if it looks like an image reference
                if '/' in pkg_name and ('docker.io' in pkg_name or 'registry' in pkg_name or pkg_name.count('/') >= 1):
                    self.log(f"Found image from package name: {pkg_name}")
                    return pkg_name

        self.log(f"No image reference found for element {element_id}")
        return None

    def _parse_purl_to_image_ref(self, purl: str) -> Optional[str]:
        """Parse a purl to extract container image reference."""
        self.log(f"_parse_purl_to_image_ref called with: {purl}")
        try:
            # Parse purl format: pkg:oci/name@version?repository_url=...
            # First check if there are query parameters anywhere in the purl
            if '?' in purl:
                purl_base, query_string = purl.split('?', 1)
                self.log(f"Found query string: {query_string}")
                query_params = dict(param.split('=') for param in query_string.split('&') if '=' in param)
                repository_url = query_params.get('repository_url')
                self.log(f"Extracted repository_url: {repository_url}")

                if repository_url:
                    # Extract version/digest info from the purl_base
                    if '@' in purl_base:
                        # Format: pkg:oci/name@version
                        if '/' in purl_base:
                            parts = purl_base.split('/')
                            if len(parts) >= 2 and '@' in parts[-1]:
                                name_version = parts[-1]
                                name, version = name_version.split('@', 1)
                                if 'sha256:' in version:
                                    result = f"{repository_url}@{version}"
                                    self.log(f"Returning with digest: {result}")
                                    return result
                                else:
                                    result = f"{repository_url}:{version}"
                                    self.log(f"Returning with tag: {result}")
                                    return result

                    # Use the repository_url as the full image reference
                    self.log(f"Returning repository_url directly: {repository_url}")
                    return repository_url

            # Fallback to original parsing without repository_url
            if '/' in purl:
                parts = purl.split('/', 2)
                if len(parts) >= 3:
                    image_part = parts[2]  # Get part after pkg:docker/ or pkg:oci/
                    self.log(f"Fallback: extracted image_part: {image_part}")

                    # Handle version/tag info
                    if '@' in image_part:
                        name_part, version_part = image_part.split('@', 1)
                        if 'sha256:' in version_part:
                            return f"{name_part}@{version_part}"
                        else:
                            return f"{name_part}:{version_part}"
                    else:
                        return image_part
        except Exception as e:
            self.log(f"Error parsing purl {purl}: {e}")
        return None

    def _extract_registry_from_purl(self, purl: str) -> Optional[str]:
        """Extract registry URL from purl query parameters."""
        try:
            if '?' in purl:
                _, query = purl.split('?', 1)
                query_params = dict(param.split('=') for param in query.split('&') if '=' in param)
                repository_url = query_params.get('repository_url')
                if repository_url:
                    self.log(f"Extracted repository_url from purl: {repository_url}")
                    return repository_url
        except Exception as e:
            self.log(f"Error extracting registry from purl {purl}: {e}")
        return None

    def calculate_manifest_size(self, manifest: Dict) -> int:
        """Calculate total size from manifest."""
        total_size = 0

        if manifest.get('mediaType') == 'application/vnd.docker.distribution.manifest.list.v2+json' or \
           manifest.get('mediaType') == 'application/vnd.oci.image.index.v1+json':
            for entry in manifest.get('manifests', []):
                total_size += entry.get('size', 0)
        else:
            if 'config' in manifest:
                total_size += manifest['config'].get('size', 0)

            for layer in manifest.get('layers', []):
                total_size += layer.get('size', 0)

        return total_size

    def extract_manifest_blobs(self, manifest: Dict) -> List[Dict[str, any]]:
        """Extract individual blob information from manifest."""
        blobs = []

        if manifest.get('mediaType') == 'application/vnd.docker.distribution.manifest.list.v2+json' or \
           manifest.get('mediaType') == 'application/vnd.oci.image.index.v1+json':
            # For image indexes, we include the manifests themselves as blobs
            for entry in manifest.get('manifests', []):
                if 'digest' in entry and 'size' in entry:
                    blobs.append({
                        'digest': entry['digest'],
                        'size': entry['size'],
                        'mediaType': entry.get('mediaType', 'application/vnd.docker.distribution.manifest.v2+json')
                    })
        else:
            # Include config blob
            if 'config' in manifest:
                config = manifest['config']
                if 'digest' in config and 'size' in config:
                    blobs.append({
                        'digest': config['digest'],
                        'size': config['size'],
                        'mediaType': config.get('mediaType', 'application/vnd.docker.container.image.v1+json')
                    })

            # Include layer blobs
            for layer in manifest.get('layers', []):
                if 'digest' in layer and 'size' in layer:
                    blobs.append({
                        'digest': layer['digest'],
                        'size': layer['size'],
                        'mediaType': layer.get('mediaType', 'application/vnd.docker.image.rootfs.diff.tar.gzip')
                    })

        return blobs

    def deduplicate_child_blobs(self, child_containers: List[Dict[str, any]], parent_containers: List[Dict[str, any]]) -> Tuple[int, List[Dict[str, any]]]:
        """
        Compare blobs between child and parent containers and return only unique child blobs.
        Returns (total_unique_size, unique_blobs_details)
        """
        # Collect all parent blob digests
        parent_digests = set()
        for parent_container in parent_containers:
            for blob in parent_container.get('blobs', []):
                parent_digests.add(blob['digest'])

        self.log(f"Found {len(parent_digests)} unique blob digests in parent containers")

        # Find unique blobs in child containers
        unique_blobs = []
        total_unique_size = 0
        duplicate_count = 0
        duplicate_size = 0

        for child_container in child_containers:
            container_url = child_container['url']
            for blob in child_container.get('blobs', []):
                blob_digest = blob['digest']
                blob_size = blob['size']

                if blob_digest in parent_digests:
                    # This blob exists in parent - skip it
                    duplicate_count += 1
                    duplicate_size += blob_size
                    self.log(f"Skipping duplicate blob {blob_digest[:12]}... (size: {blob_size}) from {container_url}")
                else:
                    # This blob is unique to the child
                    unique_blobs.append({
                        'digest': blob_digest,
                        'size': blob_size,
                        'mediaType': blob.get('mediaType', ''),
                        'container_url': container_url
                    })
                    total_unique_size += blob_size
                    self.log(f"Including unique blob {blob_digest[:12]}... (size: {blob_size}) from {container_url}")

        self.log(f"Blob deduplication results:")
        self.log(f"  - Unique blobs: {len(unique_blobs)} (total size: {total_unique_size} bytes)")
        self.log(f"  - Duplicate blobs: {duplicate_count} (total size: {duplicate_size} bytes)")

        return total_unique_size, unique_blobs

    def find_base_images_from_sbom(self, registry: str, repository: str, tag: str) -> List[Dict[str, str]]:
        """Find base and builder images by inspecting SBOM."""
        # Get the manifest digest first
        original_digest = self.get_manifest_digest(registry, repository, tag)
        if not original_digest:
            self.log(f"Could not get digest for {registry}/{repository}:{tag}")
            return []

        # Generate SBOM tag
        sbom_tag = self.get_sbom_tag(original_digest)
        self.log(f"Looking for SBOM at tag: {sbom_tag}")

        # Fetch SBOM
        sbom_data = self.get_sbom(registry, repository, sbom_tag)
        if not sbom_data:
            self.log(f"No SBOM found at {registry}/{repository}:{sbom_tag}")
            return []

        # Parse SBOM for base and builder images
        base_images = self.parse_spdx_for_base_images(sbom_data, registry=registry, repository=repository)
        if base_images:
            self.log(f"Found {len(base_images)} base/builder images from SBOM")
            for img in base_images:
                self.log(f"  {img['type']} image ({img['relationship']}): {img['image']}")
        else:
            self.log("No base/builder images found in SBOM")

        return base_images

    def get_image_source_size(self, image_url: str, image_type: str = "image") -> Dict[str, any]:
        """Get the total source container size for an image."""
        try:
            # Parse the image URL
            img_registry, img_repository, img_tag = self.parse_oci_url(image_url)
            self.log(f"Measuring {image_type} source size: {img_registry}/{img_repository}:{img_tag}")

            # Find source containers for the image
            source_containers = self.find_source_containers(img_registry, img_repository, img_tag)
            total_size = sum(container['size'] for container in source_containers)

            self.log(f"{image_type.capitalize()} source containers found: {len(source_containers)}")
            self.log(f"{image_type.capitalize()} total source size: {total_size} bytes")

            return {
                'url': image_url,
                'size': total_size,
                'container_count': len(source_containers),
                'containers': source_containers
            }

        except Exception as e:
            self.log(f"Error measuring {image_type} source size: {e}")
            return {
                'url': image_url,
                'size': 0,
                'container_count': 0,
                'containers': [],
                'error': str(e)
            }

    def find_source_containers(self, registry: str, repository: str, tag: str) -> List[Dict[str, any]]:
        """Find and measure source containers for the given artifact."""
        source_containers = []

        original_manifest = self.get_manifest(registry, repository, tag)
        if not original_manifest:
            self.log(f"Could not find manifest for {registry}/{repository}:{tag}")
            return source_containers

        if original_manifest.get('mediaType') == 'application/vnd.docker.distribution.manifest.list.v2+json' or \
           original_manifest.get('mediaType') == 'application/vnd.oci.image.index.v1+json':
            self.log("Processing image index/manifest list")

            # First check for a unified source container with the original tag
            unified_source_tag = self.get_source_container_tag(tag)
            unified_source_manifest = self.get_manifest(registry, repository, unified_source_tag)
            if unified_source_manifest:
                size = self.calculate_manifest_size(unified_source_manifest)
                blobs = self.extract_manifest_blobs(unified_source_manifest)
                source_containers.append({
                    'url': f"{registry}/{repository}:{unified_source_tag}",
                    'size': size,
                    'blobs': blobs,
                    'manifest': unified_source_manifest
                })
                self.log(f"Found unified source container: {registry}/{repository}:{unified_source_tag} ({size} bytes, {len(blobs)} blobs)")
            else:
                # Try digest-based method as fallback
                original_digest = self.get_manifest_digest(registry, repository, tag)
                if original_digest:
                    digest_source_tag = self.get_digest_based_source_tag(original_digest)
                    digest_source_manifest = self.get_manifest(registry, repository, digest_source_tag)
                    if digest_source_manifest:
                        size = self.calculate_manifest_size(digest_source_manifest)
                        blobs = self.extract_manifest_blobs(digest_source_manifest)
                        source_containers.append({
                            'url': f"{registry}/{repository}:{digest_source_tag}",
                            'size': size,
                            'blobs': blobs,
                            'manifest': digest_source_manifest
                        })
                        self.log(f"Found digest-based unified source container: {registry}/{repository}:{digest_source_tag} ({size} bytes, {len(blobs)} blobs)")

            # Then check for individual architecture source containers
            for entry in original_manifest.get('manifests', []):
                digest = entry.get('digest')
                if digest:
                    # Try method 1: digest as-is (current behavior)
                    source_tag = self.get_source_container_tag(digest)
                    source_manifest = self.get_manifest(registry, repository, source_tag)
                    if source_manifest:
                        size = self.calculate_manifest_size(source_manifest)
                        blobs = self.extract_manifest_blobs(source_manifest)
                        # Use @ for digest-based references
                        source_url = f"{registry}/{repository}@{source_tag}"
                        source_containers.append({
                            'url': source_url,
                            'size': size,
                            'blobs': blobs,
                            'manifest': source_manifest
                        })
                        self.log(f"Found arch-specific source container: {source_url} ({size} bytes, {len(blobs)} blobs)")
                    else:
                        # Try method 2: digest-based tag format
                        digest_source_tag = self.get_digest_based_source_tag(digest)
                        digest_source_manifest = self.get_manifest(registry, repository, digest_source_tag)
                        if digest_source_manifest:
                            size = self.calculate_manifest_size(digest_source_manifest)
                            blobs = self.extract_manifest_blobs(digest_source_manifest)
                            source_url = f"{registry}/{repository}:{digest_source_tag}"
                            source_containers.append({
                                'url': source_url,
                                'size': size,
                                'blobs': blobs,
                                'manifest': digest_source_manifest
                            })
                            self.log(f"Found digest-based arch-specific source container: {source_url} ({size} bytes, {len(blobs)} blobs)")
        else:
            # Try tag-based method first
            source_tag = self.get_source_container_tag(tag)
            source_manifest = self.get_manifest(registry, repository, source_tag)
            if source_manifest:
                size = self.calculate_manifest_size(source_manifest)
                blobs = self.extract_manifest_blobs(source_manifest)
                source_containers.append({
                    'url': f"{registry}/{repository}:{source_tag}",
                    'size': size,
                    'blobs': blobs,
                    'manifest': source_manifest
                })
                self.log(f"Found source container: {registry}/{repository}:{source_tag} ({size} bytes, {len(blobs)} blobs)")
            else:
                # Try digest-based method as fallback
                original_digest = self.get_manifest_digest(registry, repository, tag)
                if original_digest:
                    digest_source_tag = self.get_digest_based_source_tag(original_digest)
                    digest_source_manifest = self.get_manifest(registry, repository, digest_source_tag)
                    if digest_source_manifest:
                        size = self.calculate_manifest_size(digest_source_manifest)
                        blobs = self.extract_manifest_blobs(digest_source_manifest)
                        source_containers.append({
                            'url': f"{registry}/{repository}:{digest_source_tag}",
                            'size': size,
                            'blobs': blobs,
                            'manifest': digest_source_manifest
                        })
                        self.log(f"Found digest-based source container: {registry}/{repository}:{digest_source_tag} ({size} bytes, {len(blobs)} blobs)")

        return source_containers

    def measure_source_size(self, oci_url: str) -> Dict:
        """Main method to measure source container sizes."""
        registry, repository, tag = self.parse_oci_url(oci_url)
        self.log(f"Parsed URL - Registry: {registry}, Repository: {repository}, Tag: {tag}")

        source_containers = self.find_source_containers(registry, repository, tag)
        total_size = sum(container['size'] for container in source_containers)

        # Try to find base and builder images from SBOM
        base_builder_images = self.find_base_images_from_sbom(registry, repository, tag)
        base_builder_details = []
        all_parent_containers = []

        for img_info in base_builder_images:
            image_url = img_info['image']
            image_type = img_info['type']
            relationship = img_info['relationship']

            self.log(f"{image_type.capitalize()} image found ({relationship}): {image_url}")

            # Measure source size for this base/builder image
            size_info = self.get_image_source_size(image_url, image_type)

            if size_info['size'] > 0:
                self.log(f"{image_type.capitalize()} image source size: {size_info['size']} bytes")
                # Collect all parent source containers for blob deduplication
                all_parent_containers.extend(size_info['containers'])
            else:
                if 'error' in size_info:
                    self.log(f"{image_type.capitalize()} image source size calculation failed: {size_info['error']}")
                else:
                    self.log(f"{image_type.capitalize()} image has no source containers")

            base_builder_details.append({
                'type': image_type,
                'relationship': relationship,
                'url': image_url,
                'source_size': size_info['size'],
                'source_container_count': size_info['container_count'],
                'error': size_info.get('error')
            })

        # Calculate net source size using blob-level deduplication
        if all_parent_containers:
            self.log(f"Found {len(all_parent_containers)} parent source containers for blob deduplication")
            net_source_size, unique_blobs = self.deduplicate_child_blobs(source_containers, all_parent_containers)
            self.log(f"After blob deduplication: {net_source_size} bytes from {len(unique_blobs)} unique blobs")
        else:
            if base_builder_images:
                self.log("Base/builder images found but have no source containers or errors occurred")
            else:
                self.log("No base/builder images found in SBOM")
            net_source_size = total_size
            unique_blobs = []

        return {
            'original_artifact': f"{registry}/{repository}:{tag}",
            'source_containers': [
                {'url': container['url'], 'size': container['size']} for container in source_containers
            ],
            'total_source_size': total_size,
            'base_builder_images': base_builder_details,
            'total_base_builder_source_size': sum(detail['source_size'] for detail in base_builder_details),
            'net_source_size': net_source_size,
            'source_count': len(source_containers)
        }


def format_size(size_bytes: int) -> str:
    """Format size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def main():
    parser = argparse.ArgumentParser(
        description='Measure the size of source containers associated with OCI artifacts'
    )
    parser.add_argument('url', help='OCI artifact URL (e.g., registry.redhat.io/ubi8:latest)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-j', '--json', action='store_true', help='Output results as JSON')

    args = parser.parse_args()

    measurer = SourceContainerMeasurer(verbose=args.verbose)

    try:
        result = measurer.measure_source_size(args.url)

        if args.json:
            print(json.dumps(result, indent=2), file=sys.stderr)
        else:
            print(f"Original artifact: {result['original_artifact']}", file=sys.stderr)
            print(f"Source containers found: {result['source_count']}", file=sys.stderr)
            print(f"Total source size: {format_size(result['total_source_size'])}", file=sys.stderr)

            # Show base and builder images
            if result.get('base_builder_images'):
                print(f"\nBase/Builder images found: {len(result['base_builder_images'])}", file=sys.stderr)
                total_base_builder_size = result.get('total_base_builder_source_size', 0)
                print(f"Total base/builder source size: {format_size(total_base_builder_size)}", file=sys.stderr)
                print(f"Net source size (after subtracting base/builder): {format_size(result['net_source_size'])}", file=sys.stderr)

                print("\nBase/Builder images:", file=sys.stderr)
                for img in result['base_builder_images']:
                    status = ""
                    if img.get('error'):
                        status = f" (error: {img['error']})"
                    elif img['source_size'] == 0:
                        status = " (no source containers)"

                    print(f"  - {img['type']} ({img['relationship']}): {img['url']}", file=sys.stderr)
                    print(f"    Source size: {format_size(img['source_size'])}{status}", file=sys.stderr)
            else:
                print(f"Net source size: {format_size(result['net_source_size'])}", file=sys.stderr)

            if result['source_containers']:
                print("\nSource containers:", file=sys.stderr)
                for container in result['source_containers']:
                    print(f"  - {container['url']}: {format_size(container['size'])}", file=sys.stderr)
            else:
                print("No source containers found.", file=sys.stderr)

        # Output the net source size (after base/builder image subtraction) for scripting
        print(result['net_source_size'])

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()