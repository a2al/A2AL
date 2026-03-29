# Contributing to A2AL

## Before You Start

Open an issue before beginning significant work. This avoids duplicate effort and ensures alignment with project direction.

For bug fixes and small improvements, a PR is fine without prior discussion.

## CLA

All contributors must sign the [Contributor License Agreement](CLA.md). A bot will prompt you automatically when you open a pull request.

## Development

**Requirements:** Go 1.24+

```bash
git clone https://github.com/a2al/a2al
cd a2al
go test ./...
```

Build the daemon and CLI:

```bash
go build ./cmd/a2ald
go build ./cmd/a2al
```

## Pull Requests

- Keep PRs focused — one concern per PR
- Include tests for new behavior
- `go test ./...` must pass before submitting
- Follow existing code style; no new external dependencies without discussion

## Commit Messages

Use conventional prefixes: `feat:`, `fix:`, `docs:`, `test:`, `chore:`. Keep the subject line under 72 characters.

## License

By contributing, you agree that your contributions will be licensed under the [Mozilla Public License 2.0](LICENSE).
