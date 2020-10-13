import os
import pytest
import subprocess
import yaml

def pytest_addoption(parser):
    parser.addoption("--client-type", action="store", help="Can be of type ossl (OpenSSL) or bssl (BoringSSL)")
    parser.addoption("--test-artifacts-dir", action="store", help="test-artifacts-dir: Path to directory containing files generated during the testing process.")

# Map an OQS KEM to a BoringSSL NID
# or an OQS signature to a BoringSSL code point.
@pytest.fixture(scope="session", autouse=True)
def bssl_alg_to_id():
    bssl_generate_yml_path = os.path.join('boringssl', 'oqs_template', 'generate.yml')
    bssl_generate_yml = {}
    with open(bssl_generate_yml_path, mode='r', encoding='utf-8') as config:
        bssl_generate_yml = yaml.safe_load(config)

    mapping = {}

    # Map all the kems first
    for kex in bssl_generate_yml['kems']:
        mapping[kex['name']] = kex['nid']
        for hybrid in kex['mix_with']:
            kex_name = "{}_{}".format(hybrid['name'], kex['name'])
            mapping[kex_name] = hybrid['mix_nid']

    # Then add all the signatures
    for sig in bssl_generate_yml['sigs']:
        mapping[sig['name']] = sig['code_point']
    return mapping

@pytest.fixture
def client_type(request):
    return os.path.normpath(request.config.getoption("--client-type"))

@pytest.fixture
def test_artifacts_dir(request):
    return os.path.normpath(request.config.getoption("--test-artifacts-dir"))
