.PHONY: install test bench demo report clean

install:
	pip install -e ".[dev]"

test:
	pytest -q

bench:
	python -m nightshift.cli bench

# The money shot: break the naive integration, then show the fix holding.
demo:
	python -m nightshift.cli run --target naive --incidents
	@echo "\n\n================  SAME INTEGRATION, HARDENED  ================\n"
	python -m nightshift.cli run --target fixed

report:
	python -m nightshift.cli report --target naive -o report.html
	python -m nightshift.cli report --target fixed -o report_fixed.html
	@echo "open report.html"

clean:
	rm -f report*.html
	rm -rf __pycache__ */__pycache__ .pytest_cache
