VIRTUAL_ENV_DIR=vendor/python
BOTO_VIRTUAL_ENV_DIR=vendor/boto
PIP_CMD=PIP_DOWNLOAD_CACHE=vendor/cache $(VIRTUAL_ENV_DIR)/bin/pip install --no-deps -r 
DEPLOY_PIP_CMD=PIP_DOWNLOAD_CACHE=vendor/cache $(VIRTUAL_ENV_DIR)/bin/pip install --no-deps -r 

.PHONY: build
build: $(VIRTUAL_ENV_DIR)/lib/python2.7/site-packages/goauth

$(VIRTUAL_ENV_DIR)/lib/python2.7/site-packages/goauth/:
	virtualenv --python python2.7 --no-site-packages $(VIRTUAL_ENV_DIR)
	$(PIP_CMD) requirements.txt
	vendor/python/bin/python setup.py install

clean:
	rm -rf $(VIRTUAL_ENV_DIR)
	rm -rf build
	rm -rf dist
	rm -rf gearbox
	rm -rf *.egg
	find ./ -name "*.pyc" -delete

test: build
	$(PIP_CMD) test-requirements.txt
	$(VIRTUAL_ENV_DIR)/bin/nosetests
