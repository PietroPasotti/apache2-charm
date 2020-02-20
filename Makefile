PWD := $(shell pwd)
SOURCEDEPS_DIR ?= $(shell dirname $(PWD))/.sourcecode
HOOKS_DIR := $(PWD)/hooks
TEST_PREFIX := PYTHONPATH=$(HOOKS_DIR)
TEST_DIR := $(PWD)/hooks/tests
CHARM_DIR := $(PWD)
PYTHON := /usr/bin/env python


build: test lint proof

revision:
	@test -f revision || echo 0 > revision

proof: revision
	@echo Proofing charm...
	@(charm proof $(PWD) || [ $$? -eq 100 ]) && echo OK
	@test `cat revision` = 0 && rm revision

/usr/bin/apt:
	sudo apt-get install -y python-apt

/usr/bin/virtualenv:
	sudo apt-get install -y python-virtualenv

/usr/lib/python2.7/dist-packages/jinja2:
	sudo apt-get install -y python-jinja2

.venv: /usr/bin/apt /usr/bin/virtualenv /usr/lib/python2.7/dist-packages/jinja2
	virtualenv .venv --system-site-packages
	.venv/bin/pip install -I nose testtools mock pyyaml

test: .venv
	@echo Starting tests...
	@CHARM_DIR=$(CHARM_DIR) $(TEST_PREFIX) .venv/bin/nosetests -s $(TEST_DIR)

lint:
	@echo Checking for Python syntax...
	@flake8 $(HOOKS_DIR) --ignore=E123,E402 --exclude=$(HOOKS_DIR)/charmhelpers && echo hooks OK
	@flake8 tests --ignore=E123,E402 && echo tests OK

sourcedeps:
	@echo Updating source dependencies...
	@mkdir -p build
	@git clone lp:charm-helpers build/charm-helpers
	@$(PYTHON) build/charm-helpers/tools/charm_helpers_sync/charm_helpers_sync.py \
		-c charm-helpers.yaml \
		-r build/charm-helpers \
		-d hooks/charmhelpers
	@echo Do not forget to commit the updated files if any.

clean:
	rm -rf .venv

.PHONY: revision proof test lint sourcedeps charm-payload
