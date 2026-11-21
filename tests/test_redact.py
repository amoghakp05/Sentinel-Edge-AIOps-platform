"""
tests/test_redact.py
────────────────────
Comprehensive redaction test suite: 30+ rigorous cases covering
passwords, JWTs, AWS keys, private keys, emails, IPs, credit cards,
usernames, Shannon entropy, and tricky edge cases (JSON, URLs, punctuation).
"""

from __future__ import annotations

import json
import pytest
from collector.redact import redact_text, shannon_entropy


class TestRedactionCore:

    # 1. Plain password=
    def test_plain_password(self):
        text = "login failed password=SuperSecret42 from terminal"
        clean, cats = redact_text(text)
        assert "SuperSecret42" not in clean
        assert "[REDACTED:password]" in clean
        assert "password" in cats

    # 2. Quoted password in JSON
    def test_json_quoted_password(self):
        text = '{"auth": {"user": "admin", "password": "MySecretPass_99!"}}'
        clean, cats = redact_text(text)
        assert "MySecretPass_99!" not in clean
        assert "[REDACTED:password]" in clean
        assert "password" in cats

    # 3. Secret in URL query param
    def test_url_query_secret(self):
        text = "GET /api/v1/auth?client_id=123&secret=topsecret_token_abc HTTP/1.1"
        clean, cats = redact_text(text)
        assert "topsecret_token_abc" not in clean
        assert "[REDACTED:password]" in clean

    # 4. Bearer Token with standard JWT
    def test_bearer_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        text = f"Authorization: Bearer {jwt}"
        clean, cats = redact_text(text)
        assert jwt not in clean
        assert "[REDACTED:token]" in clean
        assert "token" in cats

    # 5. Raw JWT without 'Bearer' prefix
    def test_raw_jwt_in_log(self):
        jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZGV2In0.abc123def456ghi789jkl012mno345pqr678stu901vwx"
        text = f"Token validation for session {jwt} completed"
        clean, cats = redact_text(text)
        assert jwt not in clean
        assert "[REDACTED:token]" in clean
        assert "token" in cats

    # 6. AWS Access Key ID (AKIA...)
    def test_aws_access_key(self):
        text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        clean, cats = redact_text(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in clean
        assert "[REDACTED:api_key]" in clean
        assert "api_key" in cats

    # 7. AWS Session Key ID (ASIA...)
    def test_aws_session_key(self):
        text = "Received STS temporary credential ASIA1234567890ABCDEF"
        clean, cats = redact_text(text)
        assert "ASIA1234567890ABCDEF" not in clean
        assert "[REDACTED:api_key]" in clean

    # 8. Private Key RSA Block
    def test_rsa_private_key(self):
        key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y...\n-----END RSA PRIVATE KEY-----"
        text = f"Found ssh key: {key} in config"
        clean, cats = redact_text(text)
        assert "MIIEowIBAAKCAQEA0Y..." not in clean
        assert "[REDACTED:private_key]" in clean
        assert "private_key" in cats

    # 9. Private Key OpenSSH Block
    def test_openssh_private_key(self):
        key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE...\n-----END OPENSSH PRIVATE KEY-----"
        clean, cats = redact_text(text=key)
        assert "b3BlbnNzaC1rZXktdjE..." not in clean
        assert "[REDACTED:private_key]" in clean

    # 10. Email address
    def test_email_redaction(self):
        text = "Alert dispatched to security-lead@acme-corp.com by notification service"
        clean, cats = redact_text(text)
        assert "security-lead@acme-corp.com" not in clean
        assert "[REDACTED:email]" in clean
        assert "email" in cats

    # 11. IPv4 address
    def test_ipv4_redaction(self):
        text = "Outbound connection initiated to 198.51.100.24 on port 443"
        clean, cats = redact_text(text)
        assert "198.51.100.24" not in clean
        assert "[REDACTED:ipv4]" in clean
        assert "ipv4" in cats

    # 12. IPv6 address (full form)
    def test_ipv6_full(self):
        text = "Peer at 2001:0db8:85a3:0000:0000:8a2e:0370:7334 disconnected"
        clean, cats = redact_text(text)
        assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" not in clean
        assert "[REDACTED:ipv6]" in clean
        assert "ipv6" in cats

    # 13. IPv6 address (compressed form ::)
    def test_ipv6_compressed(self):
        text = "Packet from 2001:db8::1 dropped by firewall"
        clean, cats = redact_text(text)
        assert "2001:db8::1" not in clean
        assert "[REDACTED:ipv6]" in clean

    # 14. Credit card (16 digits with dashes)
    def test_credit_card_with_dashes(self):
        # Valid Luhn sample Visa: 4532-0150-1234-5674
        text = "Payment card 4532-0150-1234-5674 approved"
        clean, cats = redact_text(text)
        assert "4532-0150-1234-5674" not in clean
        assert "[REDACTED:credit_card]" in clean
        assert "credit_card" in cats

    # 15. Credit card (16 digits continuous)
    def test_credit_card_continuous(self):
        text = "Account charged on 4532015012345674"
        clean, cats = redact_text(text)
        assert "4532015012345674" not in clean
        assert "[REDACTED:credit_card]" in clean

    # 16. Username in auth sshd line
    def test_sshd_username_redaction(self):
        text = "sshd[1234]: Failed password for root from 10.0.0.1 port 22"
        clean, cats = redact_text(text)
        assert "root" not in clean
        assert "[REDACTED:username]" in clean
        assert "username" in cats

    # 17. Username with 'invalid user' syntax
    def test_sshd_invalid_user_redaction(self):
        text = "sshd[9999]: Failed password for invalid user deployer from 192.168.1.5"
        clean, cats = redact_text(text)
        assert "deployer" not in clean
        assert "[REDACTED:username]" in clean

    # 18. Username in key-value format (user=alice)
    def test_user_key_value(self):
        text = "audit: action=login user=alice result=success"
        clean, cats = redact_text(text)
        assert "alice" not in clean
        assert "[REDACTED:username]" in clean
        assert "username" in cats

    # 19. High-entropy random hex token
    def test_high_entropy_token(self):
        token = "9f8e7d6c5b4a3928170f1e2d3c4b5a69"
        text = f"Internal correlation blob: {token}"
        clean, cats = redact_text(text)
        assert token not in clean
        assert "[REDACTED:api_key]" in clean
        assert "api_key" in cats

    # 20. High-entropy base64 secret
    def test_high_entropy_base64(self):
        b64 = "aGFrZGprYXNkZmpoYXNkZmtqYXNkZjEyMzQ1Ng=="
        text = f"Secret header: {b64}"
        clean, cats = redact_text(text)
        assert b64 not in clean
        assert "[REDACTED:token]" in clean

    # 21. Multiple secrets in one line
    def test_multiple_secrets_single_line(self):
        text = "user=admin from 10.4.2.17 supplied password=SecretPass! with token=eyJhbGciOiJIUzI1NiJ9.e30.abcdef"
        clean, cats = redact_text(text)
        assert "admin" not in clean
        assert "10.4.2.17" not in clean
        assert "SecretPass!" not in clean
        assert "eyJhbGciOiJIUzI1NiJ9.e30.abcdef" not in clean
        assert set(cats) >= {"username", "ipv4", "password", "token"}

    # 22. Secret followed by semicolon and trailing comma
    def test_secret_with_trailing_punctuation(self):
        text = "Error config: password=hunter2; token=xyz123,"
        clean, cats = redact_text(text)
        assert "hunter2" not in clean

    # 23. Password with spaces around '='
    def test_password_spaced_equals(self):
        text = "Configuration setting: password  =  SuperSecretP@ss"
        clean, cats = redact_text(text)
        assert "SuperSecretP@ss" not in clean

    # 24. Pwd colon notation (pwd: ...)
    def test_pwd_colon_notation(self):
        text = "credentials dump: pwd: UltraSecurePassword44"
        clean, cats = redact_text(text)
        assert "UltraSecurePassword44" not in clean

    # 25. API key with hyphen (api-key: ...)
    def test_api_key_hyphen(self):
        text = "Request headers: api-key: my_super_secret_api_key_99"
        clean, cats = redact_text(text)
        assert "my_super_secret_api_key_99" not in clean

    # 26. Shannon entropy math sanity check
    def test_shannon_entropy_calculation(self):
        low_entropy = "aaaaaaaaaaaaaaaaaaaa"
        high_entropy = "aB3$kL9#mP0!xQ2&zR5*"
        assert shannon_entropy(low_entropy) == 0.0
        assert shannon_entropy(high_entropy) > 4.0

    # 27. Normal English text without secrets is uncorrupted
    def test_clean_text_unchanged(self):
        normal = "System CPU load nominal at 35 percent and disk usage stable"
        clean, cats = redact_text(normal)
        assert clean == normal
        assert len(cats) == 0

    # 28. Empty string input
    def test_empty_string(self):
        clean, cats = redact_text("")
        assert clean == ""
        assert cats == []

    # 29. Secret in nested JSON structure
    def test_nested_json_payload(self):
        payload = json.dumps({"req": {"headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.e30.secret"}}})
        clean, cats = redact_text(payload)
        assert "secret" not in clean
        assert "[REDACTED:token]" in clean

    # 30. DB Connection URI containing user and password
    def test_db_connection_uri(self):
        uri = "postgres://db_user:s3cr3t_p@ss@192.168.10.2:5432/main"
        clean, cats = redact_text(uri)
        assert "s3cr3t_p@ss" not in clean
        assert "192.168.10.2" not in clean

    # 31. Secret split by quotes and brackets
    def test_secret_in_quoted_brackets(self):
        text = "Failed config: ['secret' = 'TopSecretValue']"
        clean, cats = redact_text(text)
        assert "TopSecretValue" not in clean
