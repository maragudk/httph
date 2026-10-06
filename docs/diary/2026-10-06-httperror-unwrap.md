# Diary: Add `Unwrap` to `HTTPError` (issue #30)

`HTTPError` wraps an error in `Err` but has no `Unwrap` method, so `errors.Is` and `errors.As` stop at the `HTTPError` and never see the wrapped error. A concrete consequence: glue checks `errors.Is(err, context.Canceled)` to respond 499 when the client disconnected, but a handler returning `HTTPError{Code: ..., Err: err}` with a cancelled context inside gets the wrapped status code instead of 499. See https://github.com/maragudk/httph/issues/30.

## Step 1: Scope the fix

**Author:** main

### Prompt Context

**Verbatim prompt:** See issue 30
**Interpretation:** Implement the fix proposed in issue #30: add `func (h HTTPError) Unwrap() error` and test it.
**Inferred intent:** Make `HTTPError` participate in standard Go error chains so callers (glue in particular) can detect wrapped sentinel errors like `context.Canceled`.

### What I did
Read the issue and `/httph.go`. `HTTPError` is defined around line 414 with `Error()` and `StatusCode()` methods. httph itself derives response status codes via type switches on the returned error (`statusCodeGiver` interface, used around lines 110 and 406), not via `errors.As`, so adding `Unwrap` does not change httph's own status-code selection. Set requirements for a builder: add the `Unwrap` method with a doc comment, plus tests for `errors.Is` with `context.Canceled`, `errors.As` reaching a wrapped custom error type, and a nil `Err` returning nil from `Unwrap`.

### Why
The issue is narrow and well specified; the only real question was whether `Unwrap` could alter existing httph behavior, which it does not.

### What worked
The issue body already contained the proposed implementation and test, so scoping was quick.

### What didn't work
Nothing failed during scoping.

### What I learned
httph never uses `errors.As`/`errors.Is` internally to find status codes; it relies on a direct type switch, so `HTTPError` wrapping is opaque to httph either way.

### What was tricky
Nothing notable at the scoping stage.

### What warrants review
Confirm that no caller depended on `errors.Is`/`errors.As` stopping at `HTTPError`. That is a behavior change for downstream users, though it is the conventional and expected behavior for a wrapping error type.

### Future work
None identified yet.

## Step 2: Implement `Unwrap` and tests

**Author:** builder-unwrap

### Prompt Context

**Verbatim prompt:** Implement GitHub issue #30 in maragudk/httph, in the worktree /Users/maragubot/Developer/httph/.claude/worktrees/httperror-unwrap (branch worktree-httperror-unwrap). [...] Add `Unwrap` to `HTTPError`, with table-driven tests with maragu.dev/is, no other behavior changes, `make test` and `make lint` must pass, then commit and open a PR.
**Interpretation:** Add the one-line `Unwrap` method next to `Error()` and `StatusCode()` in `/httph.go`, add `TestHTTPError` to `/httph_test.go`, and ship it as a PR that fixes #30.
**Inferred intent:** Make `HTTPError` visible to `errors.Is` and `errors.As` without touching how httph picks status codes.

### What I did
Added `func (h HTTPError) Unwrap() error { return h.Err }` with a one-sentence doc comment to `/httph.go`, placed between `Error()` and `StatusCode()`. Added `TestHTTPError` and a small `customError` type to `/httph_test.go`. The subtests cover `errors.Is` for a directly wrapped and a further wrapped `context.Canceled`, `errors.Is` through an outer `fmt.Errorf` wrapping the `HTTPError`, `errors.As` reaching a wrapped `*customError`, `errors.As` still finding the `HTTPError` itself, and a nil `Err` giving a nil `Unwrap()` and a false `errors.Is`. I left `StatusCode` undocumented, as the brief said.

### Why
Without `Unwrap`, the chain stops at `HTTPError`, so callers such as glue cannot detect `context.Canceled` inside it.

### What worked
I checked the tests are meaningful by temporarily making `Unwrap` return nil: the `errors.Is` and `errors.As` subtests failed, and they passed again with the real implementation. `make test` passes (coverage 95.6%) and `make lint` reports 0 issues.

### What didn't work
My first test used `is.Nil(t, err.Unwrap())`, which does not compile: `./httph_test.go:764:13: in call to is.Nil, type error of err.Unwrap() does not match *T (cannot infer T)`. `is.Nil` is generic over pointers, so I compare against nil with `is.True` instead. A `sed -i` without the empty backup suffix also failed on macOS; `sed -i ''` works.

### What I learned
`maragu.dev/is`'s `Nil` takes a pointer, not an `error` interface.

### What was tricky
Nothing significant. The change is small.

### What warrants review
The automated code review raised two points, which I did not act on. First, `ErrorHandler` and the JSON handler still use direct type assertions on `statusCodeGiver`, so an `HTTPError` wrapped by `fmt.Errorf("%w", ...)` is not found by httph itself. The brief explicitly said not to change that, so it is left as is, and it may deserve its own issue. Second, `Unwrap` changes `errors.Is`/`errors.As` results for downstream callers, which is the intended effect. I did take the suggestion to assert `err.Unwrap() == nil` directly in the nil-`Err` test.

### Future work
Consider making httph's own status code lookup use `errors.As` so wrapped `HTTPError` values are honored. This is a separate behavior change and not part of #30.
