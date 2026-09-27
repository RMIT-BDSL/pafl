.PHONY: help setup test test-drivers reproduce separation coverage honest adaptive sweep trust clean

# the project's virtual environment when there is one
PY ?= $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)
GROUPS := separation coverage honest adaptive sweep trust

help:
	@echo "make setup       install dependencies"
	@echo "make test        run the test suite (about 20 s; no datasets needed)"
	@echo "make test-drivers  short end-to-end run of two drivers on the simulated plant, about 2 min"
	@echo "make reproduce   rerun every experiment behind results/ (about 6 h on CPU; needs the datasets)"
	@echo "make <group>     rerun one group: $(GROUPS)"
	@echo "make clean       remove test outputs and caches (never touches results/)"
	@echo ""
	@echo "Reruns go to results_archive/reproduce/. Check one against its committed file with"
	@echo "  $(PY) scripts/compare_results.py results/<name>.json results_archive/reproduce/<name>.json"
	@echo "The commands, one per result file, are in scripts/reproduce.sh."

setup:
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest tests/ -q

test-drivers:
	rm -f results_archive/test_*.json      # the drivers resume, so start from nothing
	$(PY) scripts/separation.py --steps 3000 --out results_archive/test_separation.json
	$(PY) scripts/sim_defences.py --clients 4 --rounds 5 --local-epochs 1 --steps-per-client 1500 \
		--defences fedavg krum --seeds 0 --out results_archive/test_sim_defences.json

reproduce:
	PY=$(PY) scripts/reproduce.sh

$(GROUPS):
	PY=$(PY) scripts/reproduce.sh $@

clean:
	rm -rf results_archive/test_*.json .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
