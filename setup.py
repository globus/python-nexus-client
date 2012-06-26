from setuptools import setup, find_packages

with open('requirements.txt') as reqs:
    install_requires = [line for line in reqs]

CONFIG = {
  'description':'client for GlobusOnline Nexus',
  'version':'0.0.1',
  'name':'nexus-client',
  'package_dir': {'':'lib'},
  'packages': find_packages(exclude=[
      "*.tests",
      "*.tests.*",
      "tests.*",
      "tests"]),
  'install_requires': install_requires,
  'tests_require': ['nose'],
  'test_suite': 'tests',
}

setup(**CONFIG)
