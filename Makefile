.PHONY: help setup test smoke day1 day1-batadal day1-swat day2 day45 report pilot clean

PY ?= python3
SEEDS ?= 0 1
CLIENTS ?= 10
ROUNDS ?= 25
STEPS ?= 4000
DEVICE ?= cpu

help:
	@echo "make setup    install dependencies"
	@echo "make test     run the test suite (about 20 s)"
	@echo "make smoke    tiny end-to-end run, no GPU, about 2 min"
	@echo "make day1     kill criterion 1: residual separation, no federated learning"
	@echo "make day1-batadal  the same criterion on real BATADAL data"
	@echo "make day1-swat     the same criterion on real SWaT, through the federation loader"
	@echo "make day2     kill criteria 2 and 3: do the defences accept, does F1 fall"
	@echo "make day45    criterion 4: the adaptive attacker"
	@echo "make report   read all results and print the go/no-go decision"
	@echo "make pilot    day1 + day2 + day45 + report"
	@echo ""
	@echo "variables: SEEDS='$(SEEDS)' CLIENTS=$(CLIENTS) ROUNDS=$(ROUNDS) DEVICE=$(DEVICE)"

setup:
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest tests/ -q

smoke:
	$(PY) scripts/day1_residuals.py --steps 3000 --out results_archive/smoke_day1.json
	$(PY) scripts/day2_defences.py --clients 4 --rounds 5 --local-epochs 1 --steps-per-client 1500 \
		--defences fedavg krum --seeds 0 --out results_archive/smoke_day2.json

day1:
	$(PY) scripts/day1_residuals.py --steps 8000 --seed 0
	$(PY) scripts/day1_residuals.py --steps 8000 --seed 0 --mined \
		--out results_archive/day1_residuals_mined.json

day1-batadal:
	$(PY) scripts/day1_residuals.py --dataset batadal --seed 0 \
		--out results/c1_batadal_expert.json
	$(PY) scripts/day1_residuals.py --dataset batadal --seed 0 --mined \
		--out results/c1_batadal_mined.json

day1-swat:
	$(PY) scripts/day1_residuals.py --dataset swat --seed 0 \
		--out results/c1_swat_narrow_shift7.json

day2:
	$(PY) scripts/day2_defences.py --clients $(CLIENTS) --rounds $(ROUNDS) --local-epochs 2 \
		--steps-per-client $(STEPS) --malicious-fractions 0.0 0.3 --seeds $(SEEDS) --device $(DEVICE) \
		--out results/sim_defences_mal30_2seed.json

day45:
	$(PY) scripts/day45_adaptive.py --clients $(CLIENTS) --rounds $(ROUNDS) --local-epochs 2 \
		--steps-per-client $(STEPS) --malicious-fraction 0.3 --seeds 0 1 2 \
		--defences fedavg fltrust trimmed_mean --device $(DEVICE) \
		--out results_archive/day45_adaptive_3seed.json

report:
	$(PY) scripts/go_nogo.py --day1 results/c1_batadal_expert.json \
		--day2 results/sim_defences_mal30_2seed.json --day45 results_archive/day45_adaptive_3seed.json

pilot: day1 day2 day45 report

clean:
	rm -rf results/*.json results/*.png results/*.pkl
