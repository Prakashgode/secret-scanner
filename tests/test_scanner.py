import os
import tempfile

import pytest

from secret_scanner.scanner import Finding, SecretScanner, _mask_secret, _shannon_entropy


@pytest.fixture
def scanner():
    return SecretScanner()


# --- AWS ---

class TestAWSKeyDetection:
    def test_detects_aws_access_key(self, scanner):
        with _temp_file("aws_key = AKIAIOSFODNN7EXAMPLE\n") as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "AWS Access Key ID" for f in findings)

    def test_detects_aws_secret_key(self, scanner):
        with _temp_file("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n") as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "AWS Secret Access Key" for f in findings)


# --- GitHub tokens ---

class TestGitHubTokenDetection:
    def test_detects_github_pat(self, scanner):
        with _temp_file("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl\n") as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "GitHub Token" for f in findings)

    def test_detects_github_service_token(self, scanner):
        with _temp_file("GHS_TOKEN=ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl\n") as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "GitHub Token" for f in findings)


# --- Private keys ---

class TestPrivateKeyDetection:
    def test_detects_rsa_private_key(self, scanner):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...\n-----END RSA PRIVATE KEY-----\n"
        with _temp_file(content) as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "Private Key" for f in findings)

    def test_detects_generic_private_key(self, scanner):
        content = "-----BEGIN PRIVATE KEY-----\nMIIEpAIBAAKCAQ...\n-----END PRIVATE KEY-----\n"
        with _temp_file(content) as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "Private Key" for f in findings)


# --- JWT ---

class TestJWTDetection:
    def test_detects_jwt_token(self, scanner):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        with _temp_file(f"auth = {jwt}\n") as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "JWT Token" for f in findings)


# --- Database URLs ---

class TestDatabaseURLDetection:
    def test_detects_postgres_url(self, scanner):
        with _temp_file("DATABASE_URL=postgres://admin:supersecret@db.example.com:5432/mydb\n") as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "Database URL" for f in findings)

    def test_detects_mysql_url(self, scanner):
        with _temp_file("DB=mysql://root:password123@localhost/app\n") as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "Database URL" for f in findings)


# --- Generic patterns ---

class TestGenericPatterns:
    def test_detects_api_key_assignment(self, scanner):
        with _temp_file("api_key = 'sk_test_fakekey1234567890abcdef'\n") as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "Generic API Key" for f in findings)

    def test_detects_password_assignment(self, scanner):
        with _temp_file("password = 'MyS3cretP@ssw0rd!'\n") as path:
            findings = scanner.scan_file(path)
            assert any(f.secret_type == "Generic Password" for f in findings)


# --- Entropy ---

class TestEntropyDetection:
    def test_detects_high_entropy_secret(self, scanner):
        with _temp_file("secret = 'a1B2c3D4e5F6g7H8i9J0kLmNoPqRsT'\n") as path:
            findings = scanner.scan_file(path)
            entropy_findings = [f for f in findings if f.secret_type == "High Entropy String"]
            assert len(entropy_findings) >= 1

    def test_low_entropy_not_flagged(self):
        entropy = _shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaa")
        assert entropy < 1.0


# --- False positives ---

class TestFalsePositives:
    def test_normal_code_not_flagged(self, scanner):
        content = (
            "def calculate_total(items):\n"
            "    return sum(item.price for item in items)\n"
        )
        with _temp_file(content) as path:
            findings = scanner.scan_file(path)
            assert len(findings) == 0

    def test_safe_url_not_flagged(self, scanner):
        with _temp_file("homepage = 'https://example.com/about'\n") as path:
            findings = scanner.scan_file(path)
            assert len(findings) == 0

    def test_placeholder_not_flagged(self, scanner):
        # short placeholder strings fall below the 20-char minimum
        with _temp_file("api_key = 'YOUR_API_KEY_HERE'\n") as path:
            findings = scanner.scan_file(path)
            api_key_findings = [f for f in findings if f.secret_type == "Generic API Key"]
            assert len(api_key_findings) == 0

    def test_binary_files_skipped(self, scanner):
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False, mode="w") as f:
            f.write("AKIAIOSFODNN7EXAMPLE")
            path = f.name
        try:
            findings = scanner.scan_file(path)
            assert len(findings) == 0
        finally:
            os.unlink(path)


# --- Utilities ---

class TestUtilities:
    def test_mask_secret(self):
        assert _mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA****************"

    def test_mask_short_string(self):
        assert _mask_secret("abc") == "***"

    def test_shannon_entropy_empty(self):
        assert _shannon_entropy("") == 0.0

    def test_shannon_entropy_uniform(self):
        entropy = _shannon_entropy("abcdefghijklmnop")
        assert entropy > 3.5

    def test_shannon_entropy_repeated(self):
        entropy = _shannon_entropy("aaaa")
        assert entropy == 0.0


# --- Directory scanning ---

class TestDirectoryScanning:
    def test_scan_directory(self, scanner):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "config.py")
            with open(filepath, "w") as f:
                f.write("AWS_KEY = AKIAIOSFODNN7EXAMPLE\n")

            findings = scanner.scan_directory(tmpdir)
            assert len(findings) >= 1
            assert any(f.secret_type == "AWS Access Key ID" for f in findings)

    def test_scan_empty_directory(self, scanner):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = scanner.scan_directory(tmpdir)
            assert len(findings) == 0


# --- Helpers ---

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
