SYSTEM_PYTHON ?= python3
VENV := .venv
PYTHON := $(VENV)/bin/python
VENV_STAMP := $(VENV)/.installed
export MPLCONFIGDIR := $(CURDIR)/.mplconfig

.NOTPARALLEL: results reproduce

.PHONY: setup env test check-artifacts demo trace baselines bounds bench simulate figures results reproduce clean

setup: env

env: $(VENV_STAMP)

$(VENV_STAMP): requirements-lock.txt
	$(SYSTEM_PYTHON) -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements-lock.txt
	touch $(VENV_STAMP)

test: env
	$(PYTHON) -m unittest discover -s code -p 'test_*.py' -v

check-artifacts:
	$(SYSTEM_PYTHON) scripts/check_artifacts.py

demo: env
	mkdir -p results
	$(PYTHON) code/llm_threshold_prototype.py --backend scripted

trace: env
	mkdir -p results
	$(PYTHON) code/llm_threshold_prototype.py --backend trace --output results/full_system_trace.json

baselines: env
	mkdir -p results
	$(PYTHON) code/authorization_baselines.py

bounds: env
	$(PYTHON) code/security_bounds.py

bench: env
	mkdir -p results
	$(PYTHON) code/threshold_bls_bench.py

simulate: env
	mkdir -p results
	$(PYTHON) code/committee_sim.py

figures: env
	mkdir -p $(MPLCONFIGDIR) figures
	$(PYTHON) code/plot_figures.py

results: demo trace baselines bounds bench simulate figures

reproduce: test results check-artifacts

clean:
	rm -rf code/__pycache__ scripts/__pycache__ $(MPLCONFIGDIR)
