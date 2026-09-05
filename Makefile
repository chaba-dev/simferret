.PHONY: check-rfds

## Validate RFD sources and the checker regression fixtures
check-rfds:
	@./scripts/check-rfd-status.sh
	@./scripts/check-rfd-status-test.sh
