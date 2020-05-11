import os
import pytest
import subprocess

def pytest_addoption(parser):
    parser.addoption("--ossl", action="store", help="ossl: Path to standalone OpenSSL executable.")
    parser.addoption("--ossl-config", action="store", help="ossl-config: Path to openssl.cnf file.")
    parser.addoption("--test-artifacts-dir", action="store", help="test-artifacts-dir: Path to directory containing files generated during the testing process.")

@pytest.fixture
def ossl_config(request):
    return os.path.normpath(request.config.getoption("--ossl-config"))

@pytest.fixture
def ossl(request):
    return os.path.normpath(request.config.getoption("--ossl"))

@pytest.fixture
def test_artifacts_dir(request):
    return os.path.normpath(request.config.getoption("--test-artifacts-dir"))
