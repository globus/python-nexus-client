VIRTUAL_ENV_DIR=dist
PIP_CMD=$(VIRTUAL_ENV_DIR)/bin/pip install --no-deps -r 
DEPLOY_PIP_CMD=PIP_DOWNLOAD_CACHE=vendor/cache $(VIRTUAL_ENV_DIR)/bin/pip install --no-deps -r 

.PHONY: build
build: $(VIRTUAL_ENV_DIR) requirements.txt

$(VIRTUAL_ENV_DIR):
	virtualenv --python python2.7 --no-site-packages $(VIRTUAL_ENV_DIR)
	$(PIP_CMD) requirements.txt
	$(VIRTUAL_ENV_DIR)/bin/python setup.py install

clean:
	rm -rf $(VIRTUAL_ENV_DIR)
	find ./ -name "*.pyc" -delete

test: build
	$(PIP_CMD) test-requirements.txt
	$(VIRTUAL_ENV_DIR)/bin/nosetests
