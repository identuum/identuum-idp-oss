# identuum-idp-oss/tools/api-docgen

Phase **P1** of the IDP docs-as-data pipeline. Emits a deterministic
YAML record per HTTP endpoint exposed by `identuum-idp-oss`.

The original design / phase docs lived in a private sibling tree and
are not bundled with the OSS module. The curated registry and tests
in this directory are the operational source of truth for what the
generator emits.

## Build + run

```bash
# From identuum-idp-oss/
go build -o bin/api-docgen ./tools/api-docgen

# Dry-run (writes YAML to stdout, no disk writes):
./bin/api-docgen --dry-run

# File output (default path: ./output/api/endpoints.yaml):
./bin/api-docgen

# Custom output directory (e.g. a mounted Hugo data directory):
./bin/api-docgen --output ../identuum-docs/data/api
```

## Properties

- Pure Go. **No Hugo dependency.** **No gograph / MCP / Claude
  dependency at runtime.** Zero new go.mod entries.
- Deterministic: two runs produce byte-identical output. No
  timestamps in the generated file.
- Sorted by `(module, surface, path, method)`.
- Curated registry (P1). AST-based extraction is deferred to P2 + P3.
- No secrets, no real tokens, no DB URLs, no PEM blocks in the
  generated output — only canonical Go import paths and short
  factual summaries.

## Editing the registry

The endpoint list lives in [`registry.go`](./registry.go) as a Go
slice. To add or update an endpoint:

1. Edit `registry.go` (each surface has its own helper function).
2. Run `go test ./tools/api-docgen/...` from the OSS root.
3. Re-run the generator to refresh `output/api/endpoints.yaml`.

The curated approach is intentional for P1. P2 will add a Go AST
extractor that reads the `Register*Routes` functions directly so the
registry can shrink to only the metadata that the AST cannot infer
(`summary`, `tier`, `auth`).
