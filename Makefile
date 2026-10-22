MAIN := main
SYSTEM_PYTHON ?= python3
VENV := .venv
PYTHON := $(VENV)/bin/python
VENV_STAMP := $(VENV)/.installed
export MPLCONFIGDIR := $(CURDIR)/.mplconfig

.NOTPARALLEL: results reproduce

.PHONY: all paper workshop infpriv setup env test check-artifacts demo trace \
	baselines bounds bench simulate figures results reproduce clean distclean

all: paper

paper: $(MAIN).pdf

workshop: anonymous_workshop.pdf

infpriv: infpriv_final.pdf

# InfPriv 2026 camera-ready variant from the same manuscript source.
infpriv_final.pdf: infpriv_final.tex main.tex references.bib neurips_infpriv_2026.sty infpriv_2026_compat.sty figures/fig_committee.pdf
	pdflatex -interaction=nonstopmode -halt-on-error infpriv_final.tex
	bibtex infpriv_final
	pdflatex -interaction=nonstopmode -halt-on-error infpriv_final.tex
	pdflatex -interaction=nonstopmode -halt-on-error infpriv_final.tex

anonymous_workshop.pdf: anonymous_workshop.tex main.tex references.bib neurips_2026.sty figures/fig_committee.pdf
	pdflatex -interaction=nonstopmode -halt-on-error anonymous_workshop.tex
	bibtex anonymous_workshop
	pdflatex -interaction=nonstopmode -halt-on-error anonymous_workshop.tex
	pdflatex -interaction=nonstopmode -halt-on-error anonymous_workshop.tex

$(MAIN).pdf: $(MAIN).tex references.bib neurips_2026.sty figures/fig_committee.pdf
	pdflatex -interaction=nonstopmode -halt-on-error $(MAIN).tex
	bibtex $(MAIN)
	pdflatex -interaction=nonstopmode -halt-on-error $(MAIN).tex
	pdflatex -interaction=nonstopmode -halt-on-error $(MAIN).tex

# Create an isolated Python environment for result reproduction.
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

# Regenerate every offline artifact used by the paper.
results: demo trace baselines bounds bench simulate figures

reproduce: test results check-artifacts

clean:
	rm -f *.aux *.bbl *.bcf *.blg *.fdb_latexmk *.fls *.log *.out *.run.xml *.synctex.gz
	rm -rf code/__pycache__ scripts/__pycache__ $(MPLCONFIGDIR)

distclean: clean
	rm -f $(MAIN).pdf anonymous_workshop.pdf infpriv_final.pdf
