.PHONY: clean tests coverage docs

all: coverage docs

clean:
	- find . -type f -name "*.pyc" -delete

tests: clean
	./runtests.py

coverage: clean
	coverage run ./runtests.py
	coverage html
	coverage report

docs:
	pushd docs && make html && popd

