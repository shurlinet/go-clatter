.PHONY: test test-hqc
# slhdsa runs separately with a larger timeout: its deep-hypertree ACVP
# vectors exceed 30m under -race (mirrors .github/workflows/ci.yml).
test:
	go test -race -count=1 -timeout 30m $$(go list ./... | grep -v /slhdsa)
	go test -race -count=1 -timeout 90m ./crypto/sign/slhdsa/...

test-hqc:
	go test -tags hqc -race -count=1 -timeout 30m $$(go list -tags hqc ./... | grep -v /slhdsa)
	go test -tags hqc -race -count=1 -timeout 90m ./crypto/sign/slhdsa/...
