## Summary

<!-- What changed, and why. -->

## Test plan

<!-- Commands you ran and their results. -->

- [ ] `go build ./... && go vet ./... && golangci-lint run ./...` clean
- [ ] `go test ./...` passing
- [ ] `go test ./... -race`, if this touches `internal/collect` or `internal/whois`
