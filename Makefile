# =================================================
#  NeoDAX Makefile
#  Default target: launch setup.sh
#  All build logic is handled by setup.sh
# =================================================

.PHONY: all setup clean install

all:
	@chmod +x setup.sh
	@bash setup.sh

clean:
	@rm -f src/*.o arch/*.o neodax neodax.exe js/neodax.node

install:
	@echo "Run setup.sh to build first, then copy neodax to your PATH manually."
