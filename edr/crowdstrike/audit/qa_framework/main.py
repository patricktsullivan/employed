# main.py

"""
Resolution Drift QA Framework - Main Pipeline

This script orchestrates the complete QA workflow:
1. Fetch recently closed alerts from CrowdStrike
2. Generate behavioral templates for each alert
3. Compare against historical consensus for similar patterns
4. Flag contradictions where analyst resolution differs from consensus
5. Generate a report for SOC lead review

Intended to run on a schedule (e.g., every 24 hours via cron).
"""

import logging
import pathlib
import sys
from datetime import datetime

import pandas as pd

from alerts_client import AlertsClient
from config import QA
from consensus import ConsensusCalculator
from report_generator import generate_reports
from sanitizer import Sanitizer, extract_qa_fields
from similarity import SimilarityAnalyzer, enrich_qa_finding_with_similarity


logger = logging.getLogger(__name__)


def run_qa_pipeline() -> int:
    """
    Execute the complete QA pipeline.
    
    Returns:
        Exit code: 0 for success, 1 for errors
    """
    start_time = datetime.now()
    logger.info(f"Starting QA pipeline at {start_time.isoformat()}")
    
    # Initialize components
    try:
        client = AlertsClient()
        calculator = ConsensusCalculator(
            min_samples=QA.min_sample_size,
            strong_threshold=QA.strong_consensus_threshold
        )
        similarity_analyzer = SimilarityAnalyzer(similarity_threshold=0.70)
    except Exception as e:
        logger.error(f"Failed to initialize components: {e}")
        return 1
    
    # -------------------------------------------------------------------------
    # Step 1: Fetch daily batch of closed alerts
    # -------------------------------------------------------------------------
    logger.info(f"Fetching alerts closed in the last {QA.batch_hours} hours...")
    
    try:
        daily_alerts = client.fetch_alerts_from_last_day(hours=QA.batch_hours)
    except Exception as e:
        logger.error(f"Failed to fetch daily alerts: {e}")
        return 1
    
    logger.info(f"Found {len(daily_alerts)} closed alerts")
    
    if not daily_alerts:
        logger.info("No alerts to process. Exiting.")
        return 0
    
    # -------------------------------------------------------------------------
    # Step 2: Process alerts and generate templates
    # -------------------------------------------------------------------------
    logger.info("Processing alerts and generating templates...")
    
    processed_alerts = []
    
    for alert in daily_alerts:
        fields = extract_qa_fields(alert)
        
        # Generate behavioral template
        template = Sanitizer.generate_template(alert)
        template_hash = Sanitizer.hash_template(template)
        
        fields['template'] = template
        fields['template_hash'] = template_hash
        
        processed_alerts.append(fields)
    
    df = pd.DataFrame(processed_alerts)
    logger.info(f"Processed {len(df)} alerts")
    
    # -------------------------------------------------------------------------
    # Step 3: Get unique pattern IDs for historical lookup
    # -------------------------------------------------------------------------
    unique_pattern_ids = df['pattern_id'].dropna().unique().tolist()
    logger.info(f"Found {len(unique_pattern_ids)} unique pattern IDs")
    
    if not unique_pattern_ids:
        logger.warning("No pattern IDs found in daily alerts. Exiting.")
        return 0
    
    # -------------------------------------------------------------------------
    # Step 4: Fetch historical baseline for these patterns
    # -------------------------------------------------------------------------
    logger.info(f"Fetching historical baseline: ({QA.lookback_days} days)...")
    
    try:
        historical_alerts = client.fetch_historical_alerts_by_pattern_id(
            pattern_ids=unique_pattern_ids,
            days=QA.lookback_days
        )
    except Exception as e:
        logger.error(f"Failed to fetch historical alerts: {e}")
        return 1
    
    if not historical_alerts:
        logger.warning("No historical alerts found. All patterns are novel.")
        historical_alerts = []
    else:
        logger.info(f"Fetched {len(historical_alerts)} historical alerts")
    
    # -------------------------------------------------------------------------
    # Step 5: Build consensus lookup and similarity index
    # -------------------------------------------------------------------------
    logger.info("Building consensus baseline and similarity index...")
    
    # Group historical resolutions by template hash
    resolution_groups: dict[str, list[str]] = {}
    
    for alert in historical_alerts:
        template = Sanitizer.generate_template(alert)
        template_hash = Sanitizer.hash_template(template)
        resolution = alert.get('resolution')
        pattern_id = alert.get('pattern_id')
        
        # Skip alerts without pattern_id - they can't participate in pattern-based consensus
        if pattern_id is None:
            continue

        # Build resolution groups for consensus calculation
        if template_hash not in resolution_groups:
            resolution_groups[template_hash] = []
        
        if resolution:
            resolution_groups[template_hash].append(resolution)
        
        # Index template for similarity analysis
        similarity_analyzer.index_template(template_hash, template, pattern_id)
    
    # Calculate consensus for each template
    consensus_lookup: dict[str, dict] = {}
    
    for template_hash, resolutions in resolution_groups.items():
        consensus_lookup[template_hash] = calculator.calculate_consensus(resolutions)
    
    logger.info(
        f"Built consensus for {len(consensus_lookup)} unique templates "
        f"({similarity_analyzer.patterns_indexed()} patterns indexed)"
    )
    
    # -------------------------------------------------------------------------
    # Step 6: Detect contradictions in daily alerts
    # -------------------------------------------------------------------------
    logger.info("Analyzing daily alerts for contradictions...")
    
    findings = []
    stats = {
        'total_processed': len(df),
        'matches_consensus': 0,
        'contradictions': 0,
        'novel_patterns': 0,
        'insufficient_data': 0,
        'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    }
    
    for _, row in df.iterrows():
        template_hash = row['template_hash']
        new_resolution = row['resolution']
        
        # Get historical consensus (or default to novel pattern)
        consensus = consensus_lookup.get(
            template_hash, 
            {'status': 'no_data', 'majority_resolution': None}
        )
        
        # Detect contradiction
        result = calculator.detect_contradiction(new_resolution, consensus)
        
        # Update statistics
        qa_severity = result.get('severity')
        if qa_severity:
            stats['by_severity'][qa_severity] = stats['by_severity'].get(qa_severity, 0) + 1
        
        reason = result.get('reason', '')
        if result['is_contradiction']:
            stats['contradictions'] += 1
        elif reason == 'matches_consensus':
            stats['matches_consensus'] += 1
        elif reason in ('novel_pattern', 'no_data'):
            stats['novel_patterns'] += 1
        elif reason == 'insufficient_historical_data':
            stats['insufficient_data'] += 1
        
        # Build finding record if noteworthy
        if result['is_contradiction'] or qa_severity == 'INFO':
            finding = {
                # Core identifiers (for JSON, hidden in HTML)
                'alert_id': row['alert_id'],
                'composite_id': row['composite_id'],
                'template_hash': template_hash,
                
                # Detection context (human-readable)
                'display_name': row.get('display_name'),
                'description': row.get('description'),
                'hostname': row['hostname'],
                'pattern_id': row['pattern_id'],
                
                # MITRE ATT&CK
                'tactic': row.get('tactic'),
                'tactic_id': row.get('tactic_id'),
                'technique': row.get('technique'),
                'technique_id': row.get('technique_id'),
                
                # CrowdStrike severity (distinct from QA severity)
                'severity_name': row.get('severity_name'),
                'confidence': row.get('confidence'),
                
                # Sensor action
                'pattern_disposition_description': row.get('pattern_disposition_description'),
                
                # QA analysis results
                'severity': qa_severity,  # QA severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
                'reason': result.get('reason'),
                'new_resolution': new_resolution,
                'historical_resolution': result.get('historical_resolution'),
                'consensus_strength': result.get('consensus_strength'),
                'historical_ratio': result.get('historical_ratio'),
                'sample_size': result.get('sample_size', consensus.get('sample_size', 0)),
                
                # Analyst info
                'analyst': row['assigned_to'],
                'seconds_to_resolved': row.get('seconds_to_resolved'),
                
                # Process chain
                'cmdline': row['cmdline'],
                'filename': row['filename'],
                'filepath': row.get('filepath'),
                'parent_filename': row.get('parent_filename'),
                'grandparent_filename': row.get('grandparent_filename'),
                
                # User context
                'user_name': row.get('user_name'),
                
                # Links
                'falcon_link': row['falcon_link'],
                
                # Timestamps
                'created_timestamp': row.get('created_timestamp'),
            }
            
            if row['pattern_id'] is not None:
                # Find similar templates for additional context
                similar_matches = similarity_analyzer.find_similar(
                    template_hash=template_hash,
                    template=row['template'],
                    pattern_id=row['pattern_id'],
                    max_results=3
                )
                
                if similar_matches:
                    finding = enrich_qa_finding_with_similarity(
                        finding, 
                        similar_matches, 
                        consensus_lookup
                    )
            
            # Ensure related_patterns exists even if empty
            if 'related_patterns' not in finding:
                finding['related_patterns'] = []

            findings.append(finding)
    
    # -------------------------------------------------------------------------
    # Step 7: Generate report
    # -------------------------------------------------------------------------
    logger.info("Generating report...")
    
    # Log summary statistics
    logger.info(f"Analysis complete:")
    logger.info(f"  Total alerts processed: {stats['total_processed']}")
    logger.info(f"  Matches consensus: {stats['matches_consensus']}")
    logger.info(f"  Contradictions: {stats['contradictions']}")
    logger.info(f"  Novel patterns: {stats['novel_patterns']}")
    logger.info(f"  Insufficient data: {stats['insufficient_data']}")
    logger.info(f"  By severity: {stats['by_severity']}")
    
    # Generate HTML and JSON reports
    report_dir = pathlib.Path(__file__).parent.resolve() / "reports"

    if findings:
        output_paths = generate_reports(
            findings=findings,
            stats=stats,
            output_dir=report_dir,
        )
        
        for fmt, path in output_paths.items():
            logger.info(f"Report saved: {path}")
        
        # Print high-priority findings summary to console
        critical_high = [x for x in findings if x.get('severity') in ('CRITICAL', 'HIGH')]
        if critical_high:
            print(f"\n{'='*60}")
            print(f"ATTENTION: {len(critical_high)} high-priority findings require review")
            print(f"{'='*60}")
            for finding in critical_high[:5]:  # Show first 5
                name = finding.get('display_name') or f"Pattern {finding.get('pattern_id')}"
                print(f"\n  [{finding['severity']}] {name}")
                print(f"    Host: {finding.get('hostname', 'Unknown')}")
                print(f"    Resolution: {finding['new_resolution']} vs historical: {finding['historical_resolution']}")
                print(f"    Analyst: {finding['analyst']}")
                print(f"    Link: {finding['falcon_link']}")
            if len(critical_high) > 5:
                print(f"\n  ... and {len(critical_high) - 5} more. See full report.")
            print(f"\nReports: {output_paths.get('html', 'N/A')}")
            print()
    else:
        logger.info("No findings to report. All alerts match consensus or are novel patterns.")
    
    # Log timing
    elapsed = datetime.now() - start_time
    logger.info(f"Pipeline completed in {elapsed.total_seconds():.1f} seconds")
    
    return 0


def main():
    """Entry point with error handling."""
    try:
        exit_code = run_qa_pipeline()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Pipeline interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Unhandled exception: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()