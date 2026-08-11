.PHONY: test fixture dev-link clean-fixture

test:
	./scripts/test.sh

fixture:
	python3 -m tests.fixture_firmware build/sparse-code-islands.bin
	python3 -m tests.fixture_firmware --low64k build/base-zero-low64k-tlv.bin

dev-link:
	./scripts/link-dev-plugin.sh

clean-fixture:
	$(RM) build/sparse-code-islands.bin build/base-zero-low64k-tlv.bin
