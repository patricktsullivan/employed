# report_generator.py

"""
Report generator for QA Framework findings.

Generates two output formats:
- HTML: Human-readable report for SOC lead review
- JSON: Machine-readable format for downstream processing

The HTML report prioritizes readability and actionability, hiding
internal identifiers while highlighting the information analysts
need to make decisions. The JSON report includes all fields for
archival and automation purposes.
"""

import html
import json
import pathlib
from datetime import datetime
from typing import Any


def generate_reports(
    findings: list[dict],
    stats: dict,
    output_dir: pathlib.Path,
    timestamp: str | None = None,
) -> dict[str, pathlib.Path]:
    """
    Generate HTML and JSON reports from QA findings.
    
    Args:
        findings: List of finding dicts from the QA pipeline
        stats: Pipeline statistics dict
        output_dir: Directory to write reports to
        timestamp: Optional timestamp string for filenames (default: current date)
        
    Returns:
        Dict mapping format name to output file path
    """
    output_dir.mkdir(exist_ok=True)
    
    if timestamp is None:
        timestamp = datetime.now().strftime('%Y-%m-%d')
    
    # Sort findings by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    sorted_findings = sorted(
        findings, 
        key=lambda f: severity_order.get(f.get('severity', 'INFO'), 5)
    )
    
    output_paths = {}
    
    # Generate JSON report (all fields)
    json_path = output_dir / f"{timestamp}_qa_findings.json"
    _write_json_report(sorted_findings, stats, json_path)
    output_paths['json'] = json_path
    
    # Generate HTML report (curated fields, formatted for humans)
    html_path = output_dir / f"{timestamp}_qa_findings.html"
    _write_html_report(sorted_findings, stats, html_path, timestamp)
    output_paths['html'] = html_path
    
    return output_paths


def _write_json_report(
    findings: list[dict], 
    stats: dict, 
    output_path: pathlib.Path
) -> None:
    """Write complete findings to JSON file."""
    report = {
        'generated_at': datetime.now().isoformat(),
        'summary': stats,
        'findings': findings,
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)


def _write_html_report(
    findings: list[dict],
    stats: dict,
    output_path: pathlib.Path,
    timestamp: str,
) -> None:
    """Write formatted HTML report."""
    html_content = _build_html_report(findings, stats, timestamp)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


def _build_html_report(
    findings: list[dict], 
    stats: dict, 
    timestamp: str
) -> str:
    """Build the complete HTML report string."""
    
    # Build findings HTML
    findings_html = ""
    for finding in findings:
        findings_html += _build_finding_card(finding)
    
    if not findings_html:
        findings_html = """
        <div class="no-findings">
            <p>No findings to report. All alerts match consensus or are novel patterns.</p>
        </div>
        """
    
    # Build analyst summary table
    analyst_summary = _build_analyst_summary(findings)
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QA Findings Report - {timestamp}</title>
    <style>
{_get_css()}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Resolution Drift QA Report</h1>
            <p class="subtitle">Generated {timestamp}</p>
        </header>
        
        <section class="summary">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{stats.get('total_processed', 0)}</div>
                    <div class="stat-label">Alerts Processed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats.get('contradictions', 0)}</div>
                    <div class="stat-label">Contradictions</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats.get('matches_consensus', 0)}</div>
                    <div class="stat-label">Match Consensus</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats.get('novel_patterns', 0)}</div>
                    <div class="stat-label">Novel Patterns</div>
                </div>
            </div>
            
            <div class="severity-breakdown">
                <h3>Findings by Severity</h3>
                <div class="severity-bars">
                    {_build_severity_bars(stats.get('by_severity', {}))}
                </div>
            </div>
            
            {analyst_summary}
        </section>
        
        <section class="findings">
            <h2>Findings ({len(findings)})</h2>
            {findings_html}
        </section>
        
        <footer>
            <p>Resolution Drift QA Framework</p>
        </footer>
    </div>
    
    <script>
{_get_javascript()}
    </script>
</body>
</html>"""


def _build_finding_card(finding: dict) -> str:
    """Build HTML for a single finding card."""
    severity = finding.get('severity', 'INFO')
    severity_class = severity.lower()
    
    # Escape user-controlled content
    hostname = html.escape(str(finding.get('hostname') or 'Unknown'))
    display_name = html.escape(str(finding.get('display_name') or f"Pattern {finding.get('pattern_id', 'Unknown')}"))
    description = html.escape(str(finding.get('description') or ''))
    analyst = html.escape(str(finding.get('analyst') or 'Unknown'))
    cmdline = html.escape(str(finding.get('cmdline') or ''))
    filename = html.escape(str(finding.get('filename') or ''))
    parent_filename = html.escape(str(finding.get('parent_filename') or ''))
    grandparent_filename = html.escape(str(finding.get('grandparent_filename') or ''))
    user_name = html.escape(str(finding.get('user_name') or ''))
    filepath = html.escape(str(finding.get('filepath') or ''))
    
    # Resolution comparison
    new_res = finding.get('new_resolution') or 'None'
    hist_res = finding.get('historical_resolution') or 'None'
    consensus_strength = finding.get('consensus_strength') or 'N/A'
    sample_size = finding.get('sample_size', 0)
    historical_ratio = finding.get('historical_ratio')
    ratio_display = f"{historical_ratio:.0%}" if historical_ratio else 'N/A'
    
    # MITRE ATT&CK context (using new array format)
    mitre_attack = finding.get('mitre_attack', [])
    mitre_html = _build_mitre_section(mitre_attack, finding)

    # CrowdStrike severity/confidence
    cs_severity = finding.get('severity_name') or ''
    cs_confidence = finding.get('confidence')
    cs_display = ""
    if cs_severity:
        cs_display = cs_severity
        if cs_confidence is not None:
            cs_display += f" ({cs_confidence}% confidence)"
    
    # Timing info
    seconds_to_resolved = finding.get('seconds_to_resolved')
    time_display = _format_duration(seconds_to_resolved) if seconds_to_resolved else ''
    
    # Sensor action
    disposition_desc = html.escape(str(finding.get('pattern_disposition_description') or ''))
    
    # Falcon link
    falcon_link = finding.get('falcon_link') or ''
    
    # Process chain
    process_chain = _build_process_chain(
        grandparent_filename, 
        parent_filename, 
        filename, 
        cmdline
    )
    
    # Related patterns
    related_patterns_html = _build_related_patterns(finding.get('related_patterns', []))
    
    return f"""
        <div class="finding-card severity-{severity_class}">
            <div class="finding-header">
                <span class="severity-badge {severity_class}">{severity}</span>
                <span class="detection-name">{display_name}</span>
                <span class="hostname">{hostname}</span>
            </div>
            
            {f'<div class="description">{description}</div>' if description else ''}
            
            <div class="finding-body">
                <div class="context-section">
                    {mitre_html}
                    {f'<div class="context-item"><span class="label">CrowdStrike:</span> {cs_display}</div>' if cs_display else ''}
                    {f'<div class="context-item"><span class="label">Sensor Action:</span> {disposition_desc}</div>' if disposition_desc else ''}
                    {f'<div class="context-item"><span class="label">User:</span> {user_name}</div>' if user_name else ''}
                    {f'<div class="context-item"><span class="label">Path:</span> <code>{filepath}</code></div>' if filepath else ''}
                </div>
                
                <div class="contradiction-section">
                    <h4>Resolution Contradiction</h4>
                    <div class="resolution-comparison">
                        <div class="resolution new">
                            <div class="res-label">Analyst Decision</div>
                            <div class="res-value">{_format_resolution(new_res)}</div>
                        </div>
                        <div class="resolution-arrow">â†’</div>
                        <div class="resolution historical">
                            <div class="res-label">Historical Consensus</div>
                            <div class="res-value">{_format_resolution(hist_res)}</div>
                            <div class="res-meta">{ratio_display} of {sample_size} alerts ({consensus_strength})</div>
                        </div>
                    </div>
                </div>
                
                <div class="process-section">
                    <h4>Process Chain</h4>
                    {process_chain}
                </div>
                
                <div class="analyst-section">
                    <span class="analyst-name">{analyst}</span>
                    {f'<span class="resolution-time">Resolved in {time_display}</span>' if time_display else ''}
                </div>
                
                {related_patterns_html}
            </div>
            
            <div class="finding-footer">
                <a href="{falcon_link}" target="_blank" class="falcon-link">View in Falcon â†’</a>
            </div>
        </div>
    """


def _build_mitre_section(mitre_attack: list[dict], finding: dict) -> str:
    """
    Build the MITRE ATT&CK display section.
    
    For single entries, displays inline. For multiple entries, creates
    an expandable section showing all tactics and techniques.
    
    Args:
        mitre_attack: List of MITRE ATT&CK entry dicts from the alert
        finding: The full finding dict (for fallback to deprecated fields)
        
    Returns:
        HTML string for the MITRE section
    """
    if not mitre_attack:
        # -------------------------------------------------------------------------
        # DEPRECATED: Fallback to flat fields for backward compatibility
        # Remove this section once CrowdStrike fully deprecates the flat fields.
        # -------------------------------------------------------------------------
        tactic = finding.get('tactic') or ''
        technique = finding.get('technique') or ''
        technique_id = finding.get('technique_id') or ''
        
        if tactic or technique:
            technique_with_id = f"{technique} ({technique_id})" if technique_id else technique
            mitre_display = f"{tactic} &rarr; {technique_with_id}" if tactic else technique_with_id
            return f'<div class="context-item"><span class="label">MITRE:</span> {mitre_display}</div>'
        # -------------------------------------------------------------------------
        # END DEPRECATED FALLBACK
        # -------------------------------------------------------------------------
        return ''
    
    # Format each MITRE entry
    entries = []
    for entry in mitre_attack:
        tactic = html.escape(str(entry.get('tactic') or ''))
        tactic_id = html.escape(str(entry.get('tactic_id') or ''))
        technique = html.escape(str(entry.get('technique') or ''))
        technique_id = html.escape(str(entry.get('technique_id') or ''))
        pattern_id = entry.get('pattern_id')
        
        # Build technique display with ID
        technique_display = f"{technique} ({technique_id})" if technique_id else technique
        
        # Build full entry display
        if tactic and technique:
            entry_display = f"{tactic} &rarr; {technique_display}"
        elif tactic:
            entry_display = f"{tactic} ({tactic_id})" if tactic_id else tactic
        elif technique:
            entry_display = technique_display
        else:
            continue  # Skip empty entries
        
        # Add pattern_id context if present
        if pattern_id:
            entry_display += f' <span class="mitre-pattern-id">[Pattern: {pattern_id}]</span>'
        
        entries.append(entry_display)
    
    if not entries:
        return ''
    
    # Single entry: display inline
    if len(entries) == 1:
        return f'<div class="context-item"><span class="label">MITRE:</span> {entries[0]}</div>'
    
    # Multiple entries: create expandable section
    primary_entry = entries[0]
    additional_count = len(entries) - 1
    
    entries_html = ''.join(f'<div class="mitre-entry">{e}</div>' for e in entries)
    
    return f"""
        <div class="context-item mitre-expandable">
            <span class="label">MITRE:</span> {primary_entry}
            <button class="toggle-mitre" onclick="toggleMitre(this)">
                +{additional_count} more
            </button>
            <div class="mitre-expanded" style="display: none;">
                {entries_html}
            </div>
        </div>
    """


def _build_process_chain(
    grandparent: str, 
    parent: str, 
    filename: str, 
    cmdline: str
) -> str:
    """Build the process chain visualization."""
    parts = []
    
    if grandparent:
        parts.append(f'<span class="process grandparent" title="Grandparent process">{grandparent}</span>')
    
    if parent:
        parts.append(f'<span class="process parent" title="Parent process">{parent}</span>')
    
    if filename:
        parts.append(f'<span class="process current" title="Detection target">{filename}</span>')
    
    chain_html = ' <span class="chain-arrow">â†’</span> '.join(parts) if parts else '<em>No process information</em>'
    
    cmdline_html = ""
    if cmdline:
        # Truncate very long command lines for display
        display_cmdline = cmdline if len(cmdline) <= 500 else cmdline[:500] + '...'
        cmdline_html = f'<div class="cmdline"><code>{display_cmdline}</code></div>'
    
    return f"""
        <div class="process-chain">{chain_html}</div>
        {cmdline_html}
    """


def _build_related_patterns(related_patterns: list[dict]) -> str:
    """Build the collapsible related patterns section."""
    if not related_patterns:
        return ""
    
    patterns_html = ""
    for rp in related_patterns:
        similarity = rp.get('similarity', 0)
        similarity_pct = f"{similarity:.0%}"
        hist_consensus = rp.get('historical_consensus') or 'Unknown'
        sample_size = rp.get('sample_size', 0)
        strength = rp.get('strength') or ''
        
        diff_tokens = rp.get('differentiating_tokens', [])
        shared_tokens = rp.get('shared_tokens', [])
        
        diff_html = ', '.join(f'<code>{html.escape(t)}</code>' for t in diff_tokens[:5]) if diff_tokens else '<em>None</em>'
        shared_html = ', '.join(f'<code>{html.escape(t)}</code>' for t in shared_tokens[:5]) if shared_tokens else '<em>None</em>'
        
        patterns_html += f"""
            <div class="related-pattern">
                <div class="rp-header">
                    <span class="similarity-badge">{similarity_pct} similar</span>
                    <span class="rp-consensus">Consensus: {_format_resolution(hist_consensus)} ({sample_size} samples, {strength})</span>
                </div>
                <div class="rp-tokens">
                    <div><span class="label">Differentiating:</span> {diff_html}</div>
                    <div><span class="label">Shared:</span> {shared_html}</div>
                </div>
            </div>
        """
    
    return f"""
        <div class="related-patterns-section">
            <button class="toggle-related" onclick="toggleRelated(this)">
                Show Related Patterns ({len(related_patterns)})
            </button>
            <div class="related-patterns-content" style="display: none;">
                {patterns_html}
            </div>
        </div>
    """


def _build_analyst_summary(findings: list[dict]) -> str:
    """Build the analyst contradiction summary table."""
    if not findings:
        return ""
    
    # Count contradictions by analyst (excluding INFO/novel patterns)
    analyst_counts: dict[str, dict[str, int]] = {}
    
    for f in findings:
        if f.get('severity') == 'INFO':
            continue
            
        analyst = f.get('analyst') or 'Unknown'
        severity = f.get('severity', 'UNKNOWN')
        
        if analyst not in analyst_counts:
            analyst_counts[analyst] = {'total': 0, 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        analyst_counts[analyst]['total'] += 1
        if severity in analyst_counts[analyst]:
            analyst_counts[analyst][severity] += 1
    
    if not analyst_counts:
        return ""
    
    # Sort by total contradictions descending
    sorted_analysts = sorted(
        analyst_counts.items(), 
        key=lambda x: x[1]['total'], 
        reverse=True
    )
    
    rows_html = ""
    for analyst, counts in sorted_analysts[:10]:  # Top 10
        rows_html += f"""
            <tr>
                <td>{html.escape(analyst)}</td>
                <td class="critical-count">{counts['CRITICAL']}</td>
                <td class="high-count">{counts['HIGH']}</td>
                <td class="medium-count">{counts['MEDIUM']}</td>
                <td class="low-count">{counts['LOW']}</td>
                <td><strong>{counts['total']}</strong></td>
            </tr>
        """
    
    return f"""
        <div class="analyst-summary">
            <h3>Contradictions by Analyst</h3>
            <table>
                <thead>
                    <tr>
                        <th>Analyst</th>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                        <th>Total</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    """


def _build_severity_bars(by_severity: dict) -> str:
    """Build the severity breakdown visualization."""
    total = sum(by_severity.values()) or 1
    
    bars_html = ""
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = by_severity.get(severity, 0)
        pct = (count / total) * 100
        
        bars_html += f"""
            <div class="severity-row">
                <span class="severity-label {severity.lower()}">{severity}</span>
                <div class="severity-bar-container">
                    <div class="severity-bar {severity.lower()}" style="width: {pct}%"></div>
                </div>
                <span class="severity-count">{count}</span>
            </div>
        """
    
    return bars_html


def _format_resolution(resolution: str | None) -> str:
    """Format resolution value for display."""
    if not resolution or resolution == 'None':
        return '<span class="res-none">None</span>'
    
    resolution_lower = resolution.lower().replace('_', ' ')
    
    css_class = {
        'true positive': 'res-tp',
        'false positive': 'res-fp',
        'ignored': 'res-ignored',
    }.get(resolution_lower, '')
    
    display = resolution.replace('_', ' ').title()
    
    if css_class:
        return f'<span class="{css_class}">{display}</span>'
    return display


def _format_duration(seconds: int | None) -> str:
    """Format seconds into human-readable duration."""
    if seconds is None:
        return ''
    
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d {hours}h" if hours else f"{days}d"


def _get_css() -> str:
    """Return the CSS styles for the HTML report."""
    return """
        :root {
            --critical: #dc2626;
            --critical-bg: #fef2f2;
            --high: #ea580c;
            --high-bg: #fff7ed;
            --medium: #ca8a04;
            --medium-bg: #fefce8;
            --low: #2563eb;
            --low-bg: #eff6ff;
            --info: #6b7280;
            --info-bg: #f9fafb;
            --tp: #dc2626;
            --fp: #16a34a;
            --ignored: #6b7280;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.5;
            color: #1f2937;
            background: #f3f4f6;
            padding: 2rem;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        header h1 {
            font-size: 1.875rem;
            font-weight: 700;
            color: #111827;
        }
        
        .subtitle {
            color: #6b7280;
            margin-top: 0.25rem;
        }
        
        h2 {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: #374151;
        }
        
        h3 {
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: #4b5563;
        }
        
        h4 {
            font-size: 0.875rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .summary {
            background: white;
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        
        .stat-card {
            background: #f9fafb;
            border-radius: 0.375rem;
            padding: 1rem;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: #111827;
        }
        
        .stat-label {
            font-size: 0.875rem;
            color: #6b7280;
        }
        
        .severity-breakdown {
            margin-bottom: 1.5rem;
        }
        
        .severity-row {
            display: flex;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        
        .severity-label {
            width: 80px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-label.critical { color: var(--critical); }
        .severity-label.high { color: var(--high); }
        .severity-label.medium { color: var(--medium); }
        .severity-label.low { color: var(--low); }
        .severity-label.info { color: var(--info); }
        
        .severity-bar-container {
            flex: 1;
            height: 8px;
            background: #e5e7eb;
            border-radius: 4px;
            margin: 0 0.75rem;
        }
        
        .severity-bar {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        
        .severity-bar.critical { background: var(--critical); }
        .severity-bar.high { background: var(--high); }
        .severity-bar.medium { background: var(--medium); }
        .severity-bar.low { background: var(--low); }
        .severity-bar.info { background: var(--info); }
        
        .severity-count {
            width: 40px;
            text-align: right;
            font-weight: 600;
            font-size: 0.875rem;
        }
        
        .analyst-summary table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }
        
        .analyst-summary th,
        .analyst-summary td {
            padding: 0.5rem;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .analyst-summary th {
            font-weight: 600;
            color: #6b7280;
        }
        
        .critical-count { color: var(--critical); }
        .high-count { color: var(--high); }
        .medium-count { color: var(--medium); }
        .low-count { color: var(--low); }
        
        .findings {
            margin-bottom: 2rem;
        }
        
        .finding-card {
            background: white;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid;
            overflow: hidden;
        }
        
        .finding-card.severity-critical { border-left-color: var(--critical); background: var(--critical-bg); }
        .finding-card.severity-high { border-left-color: var(--high); background: var(--high-bg); }
        .finding-card.severity-medium { border-left-color: var(--medium); background: var(--medium-bg); }
        .finding-card.severity-low { border-left-color: var(--low); background: var(--low-bg); }
        .finding-card.severity-info { border-left-color: var(--info); background: var(--info-bg); }
        
        .finding-header {
            padding: 1rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
            background: rgba(255,255,255,0.7);
        }
        
        .severity-badge {
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            color: white;
        }
        
        .severity-badge.critical { background: var(--critical); }
        .severity-badge.high { background: var(--high); }
        .severity-badge.medium { background: var(--medium); }
        .severity-badge.low { background: var(--low); }
        .severity-badge.info { background: var(--info); }
        
        .detection-name {
            font-weight: 600;
            color: #111827;
        }
        
        .hostname {
            color: #6b7280;
            font-family: monospace;
            font-size: 0.875rem;
        }
        
        .description {
            padding: 0 1rem 0.75rem 1rem;
            color: #4b5563;
            font-size: 0.875rem;
            background: rgba(255,255,255,0.7);
        }
        
        .finding-body {
            padding: 1rem;
            background: white;
        }
        
        .context-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem;
            margin-bottom: 1rem;
            font-size: 0.875rem;
        }
        
        .context-item {
            color: #4b5563;
        }
        
        .context-item .label {
            font-weight: 600;
            color: #6b7280;
        }
        
        /* MITRE ATT&CK expandable section styles */
        .mitre-expandable {
            grid-column: 1 / -1;
        }
        
        .toggle-mitre {
            background: #e5e7eb;
            border: none;
            border-radius: 0.25rem;
            padding: 0.125rem 0.5rem;
            font-size: 0.75rem;
            cursor: pointer;
            color: #4b5563;
            margin-left: 0.5rem;
            transition: all 0.2s;
        }
        
        .toggle-mitre:hover {
            background: #d1d5db;
        }
        
        .mitre-expanded {
            margin-top: 0.5rem;
            padding: 0.5rem;
            background: #f9fafb;
            border-radius: 0.25rem;
            border-left: 3px solid #6366f1;
        }
        
        .mitre-entry {
            padding: 0.25rem 0;
            font-size: 0.8125rem;
        }
        
        .mitre-entry:not(:last-child) {
            border-bottom: 1px solid #e5e7eb;
        }
        
        .mitre-pattern-id {
            font-size: 0.75rem;
            color: #6b7280;
            font-style: italic;
        }
        
        .contradiction-section {
            background: #f9fafb;
            border-radius: 0.375rem;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .resolution-comparison {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .resolution {
            text-align: center;
            padding: 0.75rem;
            background: white;
            border-radius: 0.375rem;
            min-width: 150px;
        }
        
        .res-label {
            font-size: 0.75rem;
            color: #6b7280;
            text-transform: uppercase;
            margin-bottom: 0.25rem;
        }
        
        .res-value {
            font-size: 1.125rem;
            font-weight: 600;
        }
        
        .res-meta {
            font-size: 0.75rem;
            color: #6b7280;
            margin-top: 0.25rem;
        }
        
        .res-tp { color: var(--tp); }
        .res-fp { color: var(--fp); }
        .res-ignored { color: var(--ignored); }
        .res-none { color: #9ca3af; font-style: italic; }
        
        .resolution-arrow {
            font-size: 1.5rem;
            color: #9ca3af;
        }
        
        .process-section {
            margin-bottom: 1rem;
        }
        
        .process-chain {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }
        
        .process {
            font-family: monospace;
            font-size: 0.875rem;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            background: #e5e7eb;
        }
        
        .process.current {
            background: #dbeafe;
            font-weight: 600;
        }
        
        .chain-arrow {
            color: #9ca3af;
        }
        
        .cmdline {
            background: #1f2937;
            color: #e5e7eb;
            padding: 0.75rem;
            border-radius: 0.375rem;
            overflow-x: auto;
            font-size: 0.8125rem;
        }
        
        .cmdline code {
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .analyst-section {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 0.875rem;
            color: #6b7280;
            margin-bottom: 1rem;
        }
        
        .analyst-name {
            font-weight: 600;
            color: #374151;
        }
        
        .resolution-time {
            font-style: italic;
        }
        
        .related-patterns-section {
            border-top: 1px solid #e5e7eb;
            padding-top: 1rem;
        }
        
        .toggle-related {
            background: none;
            border: 1px solid #d1d5db;
            border-radius: 0.375rem;
            padding: 0.5rem 1rem;
            font-size: 0.875rem;
            cursor: pointer;
            color: #4b5563;
            transition: all 0.2s;
        }
        
        .toggle-related:hover {
            background: #f3f4f6;
            border-color: #9ca3af;
        }
        
        .related-patterns-content {
            margin-top: 1rem;
        }
        
        .related-pattern {
            background: #f9fafb;
            border-radius: 0.375rem;
            padding: 0.75rem;
            margin-bottom: 0.5rem;
        }
        
        .rp-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
            margin-bottom: 0.5rem;
        }
        
        .similarity-badge {
            background: #dbeafe;
            color: #1e40af;
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
        }
        
        .rp-consensus {
            font-size: 0.875rem;
            color: #4b5563;
        }
        
        .rp-tokens {
            font-size: 0.8125rem;
            color: #6b7280;
        }
        
        .rp-tokens code {
            background: #e5e7eb;
            padding: 0.125rem 0.25rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
        }
        
        .finding-footer {
            padding: 0.75rem 1rem;
            background: #f9fafb;
            border-top: 1px solid #e5e7eb;
        }
        
        .falcon-link {
            color: #2563eb;
            text-decoration: none;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .falcon-link:hover {
            text-decoration: underline;
        }
        
        .no-findings {
            background: white;
            border-radius: 0.5rem;
            padding: 2rem;
            text-align: center;
            color: #6b7280;
        }
        
        footer {
            text-align: center;
            color: #9ca3af;
            font-size: 0.875rem;
            padding: 1rem;
        }
        
        @media (max-width: 640px) {
            body {
                padding: 1rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .resolution-comparison {
                flex-direction: column;
            }
            
            .resolution-arrow {
                transform: rotate(90deg);
            }
        }
    """


def _get_javascript() -> str:
    """Return the JavaScript for the HTML report."""
    return """
        function toggleRelated(button) {
            const content = button.nextElementSibling;
            const isHidden = content.style.display === 'none';
            
            content.style.display = isHidden ? 'block' : 'none';
            button.textContent = isHidden 
                ? button.textContent.replace('Show', 'Hide')
                : button.textContent.replace('Hide', 'Show');
        }
        
        function toggleMitre(button) {
            const content = button.nextElementSibling;
            const isHidden = content.style.display === 'none';
            
            content.style.display = isHidden ? 'block' : 'none';
            
            // Update button text to show/hide state
            const count = button.textContent.match(/\\d+/)[0];
            button.textContent = isHidden ? `Hide ${count} more` : `+${count} more`;
        }
    """