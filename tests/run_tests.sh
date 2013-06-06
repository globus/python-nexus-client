#!/bin/bash

# ./run_tests.sh <path-to-graph-repo> will reload fixtures, start Graph in 
# paster and run the REST client test cases, writing results to nosetest.out.
# Script assumes that there is a cassandra instance running in the background.

GRAPH_PATH=$1
REST_CLIENT_TEST_PATH=`pwd`
pushd $GRAPH_PATH
PYTHONPATH=$GRAPH_PATH python globusonline/graph/test_utils/fixture_loader.py -c ./development.ini -d -f $REST_CLIENT_TEST_PATH/fixtures/
paster serve ./development.ini &
sleep 6
popd
nosetests -s -a go_rest_test 2>nosetest.out
kill $!
