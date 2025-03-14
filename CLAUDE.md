# HTTPH Development Guide

## Build & Test Commands
```bash
# Run all tests
make test
# Run specific test
go test -run TestFormHandler
# Run benchmarks
make benchmark
# View coverage
make cover
# Run linter
make lint
```

## Code Style Guidelines
- **Imports**: Standard lib first, third-party after blank line, local imports last
- **Formatting**: Standard Go formatting (gofmt)
- **Types**: Interface names end with `-er`, extensive use of generics
- **Naming**: PascalCase for exported, camelCase for unexported
- **Error Handling**: Use http.Error for HTTP errors, custom HTTPError type
- **Error Messages**: Lowercase without trailing punctuation, pattern: "error <doing something>: %w"
- **Testing**: Table-driven tests with t.Run(), uses maragu.dev/is for assertions
- **Middleware**: Standard http.Handler pattern with functional options

## Project Structure
- Main package code in `httph.go`
- Tests in `httph_test.go`
- Templates in `*.gohtml` files
- Test data in `testdata/` directory