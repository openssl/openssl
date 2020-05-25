import os
import pytest
import subprocess

def pytest_addoption(parser):
    parser.addoption("--client-prog", action="store", help="client: Path to standalone TLS client program.")
    parser.addoption("--server-prog", action="store", help="server: Path to TLS server program.")
    parser.addoption("--client-type", action="store", help="Can be of type ossl (OpenSSL) or bssl (BoringSSL)")
    parser.addoption("--server-type", action="store", help="Can be of type ossl (OpenSSL) or bssl (BoringSSL)")
    parser.addoption("--test-artifacts-dir", action="store", help="test-artifacts-dir: Path to directory containing files generated during the testing process.")

@pytest.fixture
def client_prog(request):
    return os.path.join(request.config.getoption("--client-prog"))

@pytest.fixture
def server_prog(request):
    return os.path.join(request.config.getoption("--server-prog"))

@pytest.fixture
def client_type(request):
    return os.path.normpath(request.config.getoption("--client-type"))

@pytest.fixture
def server_type(request):
    return os.path.normpath(request.config.getoption("--server-type"))

@pytest.fixture
def test_artifacts_dir(request):
    return os.path.normpath(request.config.getoption("--test-artifacts-dir"))
