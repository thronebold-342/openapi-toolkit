# OpenAPI Toolkit

Two command-line tools for working with OpenAPI specs:

- **Diff Engine** — compares two versions of an OpenAPI spec (JSON or YAML) and reports breaking changes, non-breaking changes, and warnings.
- **Security Scanner** — scans a single OpenAPI spec for common security misconfigurations (hardcoded secrets, missing auth, insecure servers and more).

Both are plain Python scripts with no framework dependencies beyond PyYAML.

## Why this exists

APIs change constantly, and it's easy to accidentally ship a breaking change — a removed field, a newly-required parameter, a deleted endpoint — without realizing it until a client's integration breaks. The Diff Engine catches these automatically by comparing two spec versions.

Separately, OpenAPI specs often leak security issues that are easy to miss in review: hardcoded API keys in examples, endpoints with no auth requirement, HTTP servers instead of HTTPS. The Security Scanner checks for these patterns.

## Features

**Diff Engine**
- Detects removed/added endpoints and HTTP methods
- Detects parameter changes: added, removed, or changed from optional to required
- Detects request/response body field changes
- Detects component schema field changes
- Resolves `$ref` references before comparing, so schemas referenced via `$ref` are diffed correctly, not skipped
- Supports both JSON and YAML input, regardless of file extension

**Security Scanner**
- Hardcoded secret detection (AWS keys, GitHub tokens, generic password/secret patterns)
- Missing or empty `security` fields on endpoints
- Sensitive/admin-looking endpoint paths without auth
- Insecure (`http://`) server URLs
- Basic auth usage
- API keys passed via query parameters
- Sensitive field names in schemas (passwords, tokens, SSNs, etc.)
- Several other checks — 13 rules total, see source for the full list

## Installation

```bash
git clone https://github.com/thronebold-342/openapi-toolkit.git
cd openapi-toolkit
pip3 install -r requirements.txt
```

## Usage

**Diff Engine** — compare two spec versions:

```bash
python3 diffEngine.py
```

*(currently reads `old_spec.yaml` / `new_spec.yaml` from the working directory — CLI arguments for custom filenames are on the roadmap, see below)*
*(Also acceptes JSON OpenAPI files)*
Sample output:

```
High - REMOVED_ENDPOINT - /orders endpoint removed
High - REQUIRED_PARAMETER_ADDED - GET /users added required parameter 'role'
High - COMPONENT_FIELD_REMOVED - Schema 'User' field 'email' removed

Low - ADDED_ENDPOINT - /products endpoint added
Low - OPTIONAL_PARAMETER_ADDED - GET /users added optional parameter 'sort'
```

**Security Scanner** — scan a single spec:

```bash
python3 OpenApiScanner.py
```

*(currently reads a hardcoded filename from the working directory — see roadmap below)*

Example spec files used for testing/demo purposes are in `OpenApis_TestFiles/`.

## Roadmap & known limitations

This project is under active development. Currently on the list:

- CLI arguments for input filenames (rather than hardcoded paths)
- Exit codes so the tools can gate CI pipelines
- File-based report output (Markdown/HTML/JSON), not just console printing
- Security requirement diffing in the Diff Engine (auth changes between spec versions)
- Support for multiple content types beyond `application/json`
- A test suite

Contributions and suggestions welcome via issues.

## License

MIT — see [LICENSE](LICENSE).
