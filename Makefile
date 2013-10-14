.PHONY: clean tests coverage docs

all: coverage docs

clean:
	- find . -type f -name "*.pyc" -delete

tests: clean
	./runtests.py

coverage: clean dev-env
	coverage run ./runtests.py
	coverage html
	coverage report

docs: clean
	pushd docs && make html && popd

dist: clean
	python setup.py sdist

# virtualenv for contributing
dev-env: dev-env/bin/activate clean
dev-env/bin/activate: dev_requirements.txt clean
	test -d venv || virtualenv dev-env
	. dev-env/bin/activate; pip install -Ur requirements.txt
	touch dev-env/bin/activate

