import os
import tempfile
import pytest
from secret_scanner.scanner import SecretScanner, _mask_secret


@pytest.fixture
def scanner():
    return SecretScanner()


def test_detects_aws_access_key(scanner):
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write("aws_key = AKIAIOSFODNN7EXAMPLE\n")
    try:
        findings = scanner.scan_file(path)
        assert any(f.secret_type == "AWS Access Key ID" for f in findings)
    finally:
        os.unlink(path)


def test_detects_password(scanner):
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write("password = 'MyS3cretP@ssw0rd!'\n")
    try:
        findings = scanner.scan_file(path)
        assert any(f.secret_type == "Generic Password" for f in findings)
    finally:
        os.unlink(path)


def test_mask_secret():
    assert _mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA****************"
    assert _mask_secret("abc") == "***"
