# test_report_generator.py

"""
Tests for the report generator module.
"""

import json
import pathlib
import tempfile

import pytest

from report_generator import (
    generate_reports,
    _format_duration,
    _format_resolution,
    _build_process_chain,
    _build_severity_bars,
    _build_analyst_summary,
)


class TestGenerateReports:
    """Tests for the main report generation function."""

    @pytest.fixture
    def sample_findings(self):
        """Sample findings for testing."""
        return [
            {
                'alert_id': 'ldt:abc123:456',
                'composite_id': 'abc123:ind:456',
                'template_hash': 'hash123',
                'display_name': 'Suspicious PowerShell Execution',
                'description': 'PowerShell executed with encoded command',
                'hostname': 'WORKSTATION-001',
                'pattern_id': 50007,
                'tactic': 'Execution',
                'tactic_id': 'TA0002',
                'technique': 'PowerShell',
                'technique_id': 'T1059.001',
                'severity_name': 'High',
                'confidence': 85,
                'severity': 'CRITICAL',
                'reason': 'contradicts_consensus',
                'new_resolution': 'false_positive',
                'historical_resolution': 'true_positive',
                'consensus_strength': 'strong',
                'historical_ratio': 0.95,
                'sample_size': 150,
                'analyst': 'analyst@example.com',
                'seconds_to_resolved': 3600,
                'cmdline': 'powershell.exe -enc SGVsbG8=',
                'filename': 'powershell.exe',
                'filepath': 'C:\\Windows\\System32\\powershell.exe',
                'parent_filename': 'cmd.exe',
                'grandparent_filename': 'explorer.exe',
                'user_name': 'jsmith',
                'falcon_link': 'https://falcon.crowdstrike.com/activity/detections/detail/abc123',
                'related_patterns': [
                    {
                        'template_hash': 'hash456',
                        'similarity': 0.85,
                        'historical_consensus': 'true_positive',
                        'sample_size': 50,
                        'strength': 'strong',
                        'differentiating_tokens': ['bypass', 'hidden'],
                        'shared_tokens': ['powershell', 'enc'],
                    }
                ],
            },
            {
                'alert_id': 'ldt:def456:789',
                'composite_id': 'def456:ind:789',
                'template_hash': 'hash789',
                'display_name': 'Suspicious Network Connection',
                'hostname': 'SERVER-002',
                'pattern_id': 50102,
                'severity': 'INFO',
                'reason': 'novel_pattern',
                'new_resolution': 'true_positive',
                'historical_resolution': None,
                'sample_size': 0,
                'analyst': 'analyst2@example.com',
                'cmdline': 'curl http://example.com',
                'filename': 'curl.exe',
                'falcon_link': 'https://falcon.crowdstrike.com/activity/detections/detail/def456',
                'related_patterns': [],
            },
        ]

    @pytest.fixture
    def sample_stats(self):
        """Sample statistics for testing."""
        return {
            'total_processed': 100,
            'matches_consensus': 85,
            'contradictions': 10,
            'novel_patterns': 5,
            'insufficient_data': 0,
            'by_severity': {
                'CRITICAL': 2,
                'HIGH': 3,
                'MEDIUM': 3,
                'LOW': 2,
                'INFO': 5,
            },
        }

    def test_generate_reports_creates_both_files(self, sample_findings, sample_stats):
        """Should create both HTML and JSON report files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = pathlib.Path(tmpdir)
            
            result = generate_reports(
                findings=sample_findings,
                stats=sample_stats,
                output_dir=output_dir,
                timestamp='2025-01-08',
            )
            
            assert 'html' in result
            assert 'json' in result
            assert result['html'].exists()
            assert result['json'].exists()

    def test_generate_reports_json_structure(self, sample_findings, sample_stats):
        """JSON report should have correct structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = pathlib.Path(tmpdir)
            
            result = generate_reports(
                findings=sample_findings,
                stats=sample_stats,
                output_dir=output_dir,
            )
            
            with open(result['json']) as f:
                data = json.load(f)
            
            assert 'generated_at' in data
            assert 'summary' in data
            assert 'findings' in data
            assert data['summary'] == sample_stats
            assert len(data['findings']) == 2

    def test_generate_reports_json_preserves_all_fields(self, sample_findings, sample_stats):
        """JSON report should preserve all finding fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = pathlib.Path(tmpdir)
            
            result = generate_reports(
                findings=sample_findings,
                stats=sample_stats,
                output_dir=output_dir,
            )
            
            with open(result['json']) as f:
                data = json.load(f)
            
            # Check first finding has all expected fields
            finding = data['findings'][0]
            assert finding['alert_id'] == 'ldt:abc123:456'
            assert finding['template_hash'] == 'hash123'
            assert finding['related_patterns'] is not None
            assert len(finding['related_patterns']) == 1

    def test_generate_reports_html_contains_findings(self, sample_findings, sample_stats):
        """HTML report should contain finding information."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = pathlib.Path(tmpdir)
            
            result = generate_reports(
                findings=sample_findings,
                stats=sample_stats,
                output_dir=output_dir,
            )
            
            html_content = result['html'].read_text()
            
            # Check for key content
            assert 'WORKSTATION-001' in html_content
            assert 'Suspicious PowerShell Execution' in html_content
            assert 'analyst@example.com' in html_content
            assert 'CRITICAL' in html_content

    def test_generate_reports_html_escapes_content(self, sample_stats):
        """HTML report should escape potentially dangerous content."""
        malicious_findings = [
            {
                'alert_id': 'test',
                'hostname': '<script>alert("xss")</script>',
                'severity': 'HIGH',
                'new_resolution': 'true_positive',
                'historical_resolution': 'false_positive',
                'analyst': 'test',
                'falcon_link': 'https://example.com',
                'cmdline': '<img src=x onerror=alert(1)>',
                'filename': 'test.exe',
                'related_patterns': [],
            }
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = pathlib.Path(tmpdir)
            
            result = generate_reports(
                findings=malicious_findings,
                stats=sample_stats,
                output_dir=output_dir,
            )
            
            html_content = result['html'].read_text()
            
            # User-provided content should be escaped
            # The hostname should be escaped (not raw script tag)
            assert '&lt;script&gt;alert' in html_content
            # The cmdline should be escaped
            assert '&lt;img src=x onerror=alert(1)&gt;' in html_content

    def test_generate_reports_empty_findings(self, sample_stats):
        """Should handle empty findings list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = pathlib.Path(tmpdir)
            
            result = generate_reports(
                findings=[],
                stats=sample_stats,
                output_dir=output_dir,
            )
            
            assert result['html'].exists()
            html_content = result['html'].read_text()
            assert 'No findings to report' in html_content

    def test_generate_reports_sorts_by_severity(self, sample_stats):
        """Findings should be sorted by severity (CRITICAL first)."""
        findings = [
            {'severity': 'INFO', 'alert_id': '1', 'hostname': 'h1', 'new_resolution': 'tp', 
             'historical_resolution': None, 'analyst': 'a', 'falcon_link': 'l', 
             'cmdline': 'c', 'filename': 'f', 'related_patterns': []},
            {'severity': 'CRITICAL', 'alert_id': '2', 'hostname': 'h2', 'new_resolution': 'fp',
             'historical_resolution': 'tp', 'analyst': 'a', 'falcon_link': 'l',
             'cmdline': 'c', 'filename': 'f', 'related_patterns': []},
            {'severity': 'HIGH', 'alert_id': '3', 'hostname': 'h3', 'new_resolution': 'tp',
             'historical_resolution': 'fp', 'analyst': 'a', 'falcon_link': 'l',
             'cmdline': 'c', 'filename': 'f', 'related_patterns': []},
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = pathlib.Path(tmpdir)
            
            result = generate_reports(
                findings=findings,
                stats=sample_stats,
                output_dir=output_dir,
            )
            
            with open(result['json']) as f:
                data = json.load(f)
            
            severities = [f['severity'] for f in data['findings']]
            assert severities == ['CRITICAL', 'HIGH', 'INFO']


class TestFormatDuration:
    """Tests for duration formatting."""

    def test_format_seconds(self):
        """Durations under a minute should show seconds."""
        assert _format_duration(30) == '30s'
        assert _format_duration(59) == '59s'

    def test_format_minutes(self):
        """Durations under an hour should show minutes."""
        assert _format_duration(60) == '1m'
        assert _format_duration(120) == '2m'
        assert _format_duration(3599) == '59m'

    def test_format_hours(self):
        """Durations under a day should show hours."""
        assert _format_duration(3600) == '1h'
        assert _format_duration(7200) == '2h'
        assert _format_duration(7260) == '2h 1m'

    def test_format_days(self):
        """Durations over a day should show days."""
        assert _format_duration(86400) == '1d'
        assert _format_duration(90000) == '1d 1h'

    def test_format_none(self):
        """None should return empty string."""
        assert _format_duration(None) == ''


class TestFormatResolution:
    """Tests for resolution formatting."""

    def test_format_true_positive(self):
        """True positive should have correct class."""
        result = _format_resolution('true_positive')
        assert 'res-tp' in result
        assert 'True Positive' in result

    def test_format_false_positive(self):
        """False positive should have correct class."""
        result = _format_resolution('false_positive')
        assert 'res-fp' in result
        assert 'False Positive' in result

    def test_format_ignored(self):
        """Ignored should have correct class."""
        result = _format_resolution('ignored')
        assert 'res-ignored' in result
        assert 'Ignored' in result

    def test_format_none(self):
        """None should show 'None' with styling."""
        result = _format_resolution(None)
        assert 'res-none' in result
        assert 'None' in result

    def test_format_unknown(self):
        """Unknown resolutions should be title-cased."""
        result = _format_resolution('some_other_status')
        assert 'Some Other Status' in result


class TestBuildProcessChain:
    """Tests for process chain building."""

    def test_full_chain(self):
        """Should display full process chain."""
        result = _build_process_chain(
            grandparent='explorer.exe',
            parent='cmd.exe',
            filename='powershell.exe',
            cmdline='powershell.exe -enc ABC',
        )
        
        assert 'explorer.exe' in result
        assert 'cmd.exe' in result
        assert 'powershell.exe' in result
        assert 'powershell.exe -enc ABC' in result

    def test_partial_chain(self):
        """Should handle missing grandparent."""
        result = _build_process_chain(
            grandparent='',
            parent='cmd.exe',
            filename='powershell.exe',
            cmdline='',
        )
        
        assert 'explorer' not in result.lower()
        assert 'cmd.exe' in result
        assert 'powershell.exe' in result

    def test_no_cmdline(self):
        """Should handle missing command line."""
        result = _build_process_chain(
            grandparent='',
            parent='',
            filename='test.exe',
            cmdline='',
        )
        
        assert 'test.exe' in result
        assert 'cmdline' not in result.lower() or 'class="cmdline"' not in result

    def test_empty_chain(self):
        """Should handle completely empty process info."""
        result = _build_process_chain(
            grandparent='',
            parent='',
            filename='',
            cmdline='',
        )
        
        assert 'No process information' in result


class TestBuildSeverityBars:
    """Tests for severity bar building."""

    def test_all_severities(self):
        """Should include all severity levels."""
        by_severity = {
            'CRITICAL': 5,
            'HIGH': 10,
            'MEDIUM': 15,
            'LOW': 10,
            'INFO': 5,
        }
        
        result = _build_severity_bars(by_severity)
        
        assert 'CRITICAL' in result
        assert 'HIGH' in result
        assert 'MEDIUM' in result
        assert 'LOW' in result
        assert 'INFO' in result

    def test_zero_counts(self):
        """Should handle zero counts."""
        by_severity = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
        }
        
        result = _build_severity_bars(by_severity)
        
        # Should still render all severity rows
        assert 'CRITICAL' in result
        assert '>0<' in result  # Count of 0


class TestBuildAnalystSummary:
    """Tests for analyst summary table building."""

    def test_multiple_analysts(self):
        """Should show multiple analysts sorted by count."""
        findings = [
            {'severity': 'CRITICAL', 'analyst': 'alice@example.com'},
            {'severity': 'CRITICAL', 'analyst': 'alice@example.com'},
            {'severity': 'HIGH', 'analyst': 'bob@example.com'},
        ]
        
        result = _build_analyst_summary(findings)
        
        assert 'alice@example.com' in result
        assert 'bob@example.com' in result

    def test_excludes_info_severity(self):
        """INFO severity findings should not count as contradictions."""
        findings = [
            {'severity': 'INFO', 'analyst': 'alice@example.com'},
            {'severity': 'INFO', 'analyst': 'alice@example.com'},
        ]
        
        result = _build_analyst_summary(findings)
        
        # Should return empty string since no contradictions
        assert result == ""

    def test_empty_findings(self):
        """Should return empty string for empty findings."""
        result = _build_analyst_summary([])
        assert result == ""

    def test_limits_to_top_10(self):
        """Should only show top 10 analysts."""
        findings = [
            {'severity': 'HIGH', 'analyst': f'analyst{i}@example.com'}
            for i in range(15)
        ]
        
        result = _build_analyst_summary(findings)
        
        # Count table rows (excluding header)
        row_count = result.count('<tr>') - 1  # Subtract header row
        assert row_count <= 10