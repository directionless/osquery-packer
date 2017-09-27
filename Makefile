# Use bash, since we're using diff <()
SHELL := /bin/bash

all:

test: test-hierarchical test-osquery-monitoring

test-%:
	python osquery-packer.py -i test-cases/$* -o test-cases/$*-test-output
	diff <(jq -S . test-cases/$*.conf) test-cases/$*-test-output
