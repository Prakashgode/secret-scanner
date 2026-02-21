import os
import tempfile
import pytest
from secret_scanner.scanner import SecretScanner, _mask_secret


@pytest.fixture
def scanner():
    return SecretScanner()


class _temp_file:
    """Context manager for a temp file with given content."""
    def __init__(self, content: str):
        self.content = content
        self.path = None

    def __enter__(self) -> str:
        fd, self.path = tempfile.mkstemp(suffix=".py")
        with os.fdopen(fd, "w") as f:
            f.write(self.content)
        return self.path

    def __exit__(self, *args):
        if self.path and os.path.exists(self.path):
            os.unlink(self.path)


def test_detects_aws_access_key(scanner):
    with _temp_file("aws_key = AKIAIOSFODNN7EXAMPLE\n") as path:
        findings = scanner.scan_file(path)
        assert any(f.secret_type == "AWS Access Key ID" for f in findings)


def test_detects_aws_secret_key(scanner):
    with _temp_file("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n") as path:
        findings = scanner.scan_file(path)
        assert any(f.secret_type == "AWS Secret Access Key" for f in findings)


def test_detects_github_pat(scanner):
    with _temp_file("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl\n") as path:
        findings = scanner.scan_file(path)
        assert any(f.secret_type == "GitHub Token" for f in findings)


def test_detects_jwt(scanner):
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    with _temp_file(f"auth = {jwt}\n") as path:
        findings = scanner.scan_file(path)
        assert any(f.secret_type == "JWT Token" for f in findings)


def test_detects_password(scanner):
    with _temp_file("password = 'MyS3cretP@ssw0rd!'\n") as path:
        findings = scanner.scan_file(path)
        assert any(f.secret_type == "Generic Password" for f in findings)


def test_mask_secret():
    assert _mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA****************"
    assert _mask_secret("abc") == "***"


def test_normal_code_not_flagged(scanner):
    content = "def calculate_total(items):\n    return sum(item.price for item in items)\n"
    with _temp_file(content) as path:
        findings = scanner.scan_file(path)
        assert len(findings) == 0


def test_binary_files_skipped(scanner):
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False, mode="w") as f:
        f.write("AKIAIOSFODNN7EXAMPLE")
        path = f.name
    try:
        findings = scanner.scan_file(path)
        assert len(findings) == 0
    finally:
        os.unlink(path)
