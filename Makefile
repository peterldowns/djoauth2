.PHONY: clean tests coverage docs

# virtualenv for contributing
dev-env: dev-env/bin/activate
dev-env/bin/activate: dev_requirements.txt clean
	test -d dev-env || virtualenv dev-env
	. dev-env/bin/activate; pip install -Ur dev_requirements.txt

clean:
	- find . -type f -name "*.pyc" -delete

tests: clean
	./runtests.py

coverage: clean
	coverage run ./runtests.py
	coverage html
	coverage report

docs: clean
	pushd docs && make html && popd

dist: clean
	python setup.py sdist

