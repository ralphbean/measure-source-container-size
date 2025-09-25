# measure-source-size.py

Measures the size of source containers associated with OCI artifacts.

## Usage

```bash
./measure-source-size.py registry.redhat.io/ubi8:latest
./measure-source-size.py -v quay.io/myorg/myapp:v1.0
./measure-source-size.py -j registry.io/repo:tag
```

## Options

- `-v, --verbose`: Enable verbose output to stderr
- `-j, --json`: Output results as JSON to stderr
- `-h, --help`: Show help message

## Output

- **stdout**: Total size in bytes (for scripting)
- **stderr**: Detailed information and logs

## Authentication

Uses standard Docker/Podman credential storage. No configuration needed if you're already authenticated with `docker login` or `podman login`.

## Documentation

See [CLAUDE.md](CLAUDE.md) for detailed technical information, architecture, and examples.