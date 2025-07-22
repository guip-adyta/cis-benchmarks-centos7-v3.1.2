.PHONY: fetch run prune
SELF=$(firstword $(MAKEFILE_LIST))
TIMESTAMP=$(shell date +%s)
OUTPUT=cis_$(TIMESTAMP).txt
fetch:
	@curl -LO https://raw.githubusercontent.com/guip-adyta/cis-benchmarks-centos7-v3.1.2/main/cis_audit.py && \
		chmod 750 cis_audit.py
	@curl -LO https://raw.githubusercontent.com/guip-adyta/cis-benchmarks-centos7-v3.1.2/main/cis_parser.py && \
		chmod 750 cis_parser.py
run:
	@./cis_audit.py > $(OUTPUT)
	@./cis_parser.py -i $(OUTPUT) # -q 1.1
prune:
	@rm cis_*.py cis_*.txt $(SELF)