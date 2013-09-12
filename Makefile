.PHONY: clean test docs

all: test

clean:
	- find . -type f -name "*.pyc" -delete

test: clean
	python runtests.py

docs:
	pushd docs && make html && popd

