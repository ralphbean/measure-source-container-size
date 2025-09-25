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
                return json.loads(response.read().decode('utf-8'))
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
                            return json.loads(response.read().decode('utf-8'))
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

    def find_source_containers(self, registry: str, repository: str, tag: str) -> List[Tuple[str, int]]:
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
                source_containers.append((f"{registry}/{repository}:{unified_source_tag}", size))
                self.log(f"Found unified source container: {registry}/{repository}:{unified_source_tag} ({size} bytes)")
            else:
                # Try digest-based method as fallback
                original_digest = self.get_manifest_digest(registry, repository, tag)
                if original_digest:
                    digest_source_tag = self.get_digest_based_source_tag(original_digest)
                    digest_source_manifest = self.get_manifest(registry, repository, digest_source_tag)
                    if digest_source_manifest:
                        size = self.calculate_manifest_size(digest_source_manifest)
                        source_containers.append((f"{registry}/{repository}:{digest_source_tag}", size))
                        self.log(f"Found digest-based unified source container: {registry}/{repository}:{digest_source_tag} ({size} bytes)")

            # Then check for individual architecture source containers
            for entry in original_manifest.get('manifests', []):
                digest = entry.get('digest')
                if digest:
                    # Try method 1: digest as-is (current behavior)
                    source_tag = self.get_source_container_tag(digest)
                    source_manifest = self.get_manifest(registry, repository, source_tag)
                    if source_manifest:
                        size = self.calculate_manifest_size(source_manifest)
                        # Use @ for digest-based references
                        source_url = f"{registry}/{repository}@{source_tag}"
                        source_containers.append((source_url, size))
                        self.log(f"Found arch-specific source container: {source_url} ({size} bytes)")
                    else:
                        # Try method 2: digest-based tag format
                        digest_source_tag = self.get_digest_based_source_tag(digest)
                        digest_source_manifest = self.get_manifest(registry, repository, digest_source_tag)
                        if digest_source_manifest:
                            size = self.calculate_manifest_size(digest_source_manifest)
                            source_url = f"{registry}/{repository}:{digest_source_tag}"
                            source_containers.append((source_url, size))
                            self.log(f"Found digest-based arch-specific source container: {source_url} ({size} bytes)")
        else:
            # Try tag-based method first
            source_tag = self.get_source_container_tag(tag)
            source_manifest = self.get_manifest(registry, repository, source_tag)
            if source_manifest:
                size = self.calculate_manifest_size(source_manifest)
                source_containers.append((f"{registry}/{repository}:{source_tag}", size))
                self.log(f"Found source container: {registry}/{repository}:{source_tag} ({size} bytes)")
            else:
                # Try digest-based method as fallback
                original_digest = self.get_manifest_digest(registry, repository, tag)
                if original_digest:
                    digest_source_tag = self.get_digest_based_source_tag(original_digest)
                    digest_source_manifest = self.get_manifest(registry, repository, digest_source_tag)
                    if digest_source_manifest:
                        size = self.calculate_manifest_size(digest_source_manifest)
                        source_containers.append((f"{registry}/{repository}:{digest_source_tag}", size))
                        self.log(f"Found digest-based source container: {registry}/{repository}:{digest_source_tag} ({size} bytes)")

        return source_containers

    def measure_source_size(self, oci_url: str) -> Dict:
        """Main method to measure source container sizes."""
        registry, repository, tag = self.parse_oci_url(oci_url)
        self.log(f"Parsed URL - Registry: {registry}, Repository: {repository}, Tag: {tag}")

        source_containers = self.find_source_containers(registry, repository, tag)

        total_size = sum(size for _, size in source_containers)

        return {
            'original_artifact': f"{registry}/{repository}:{tag}",
            'source_containers': [
                {'url': url, 'size': size} for url, size in source_containers
            ],
            'total_source_size': total_size,
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

            if result['source_containers']:
                print("\nSource containers:", file=sys.stderr)
                for container in result['source_containers']:
                    print(f"  - {container['url']}: {format_size(container['size'])}", file=sys.stderr)
            else:
                print("No source containers found.", file=sys.stderr)

        print(result['total_source_size'])

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()