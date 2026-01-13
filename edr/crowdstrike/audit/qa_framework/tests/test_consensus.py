# test_consensus.py

"""
Tests for the ConsensusCalculator class.

These tests verify that:
1. Consensus is calculated correctly with Wilson confidence intervals
2. Insufficient data is properly identified
3. Contradictions are detected with appropriate severity levels
4. Edge cases are handled gracefully
"""

import pytest
from consensus import ConsensusCalculator


class TestConsensusCalculatorInit:
    """Tests for ConsensusCalculator initialization."""

    def test_default_parameters(self):
        """Default parameters should be reasonable."""
        calc = ConsensusCalculator()
        
        assert calc.min_samples == 20
        assert calc.strong_threshold == 0.90

    def test_custom_parameters(self):
        """Custom parameters should be accepted."""
        calc = ConsensusCalculator(min_samples=10, strong_threshold=0.85)
        
        assert calc.min_samples == 10
        assert calc.strong_threshold == 0.85


class TestCalculateConsensus:
    """Tests for consensus calculation."""

    def test_strong_consensus_true_positive(self):
        """95/100 true_positive should be strong consensus."""
        calc = ConsensusCalculator(min_samples=20, strong_threshold=0.90)
        resolutions = ['true_positive'] * 95 + ['false_positive'] * 5
        
        result = calc.calculate_consensus(resolutions)
        
        assert result['status'] == 'consensus'
        assert result['majority_resolution'] == 'true_positive'
        assert result['ratio'] == 0.95
        assert result['sample_size'] == 100
        assert result['strength'] == 'strong'

    def test_moderate_consensus(self):
        """85/100 should be moderate consensus."""
        calc = ConsensusCalculator(min_samples=20, strong_threshold=0.90)
        resolutions = ['true_positive'] * 85 + ['false_positive'] * 15
        
        result = calc.calculate_consensus(resolutions)
        
        assert result['status'] == 'consensus'
        assert result['strength'] == 'moderate'
        assert result['ratio'] == 0.85

    def test_weak_consensus(self):
        """70/100 should be weak consensus."""
        calc = ConsensusCalculator(min_samples=20, strong_threshold=0.90)
        resolutions = ['true_positive'] * 70 + ['false_positive'] * 30
        
        result = calc.calculate_consensus(resolutions)
        
        assert result['status'] == 'consensus'
        assert result['strength'] == 'weak'
        assert result['ratio'] == 0.7

    def test_insufficient_data(self):
        """Sample size below min_samples should return insufficient_data."""
        calc = ConsensusCalculator(min_samples=20, strong_threshold=0.90)
        resolutions = ['true_positive'] * 15 + ['false_positive'] * 3
        
        result = calc.calculate_consensus(resolutions)
        
        assert result['status'] == 'insufficient_data'
        assert result['sample_size'] == 18
        assert result['strength'] is None
        # Should still provide majority info
        assert result['majority_resolution'] == 'true_positive'

    def test_no_data(self):
        """Empty list should return no_data."""
        calc = ConsensusCalculator()
        
        result = calc.calculate_consensus([])
        
        assert result['status'] == 'no_data'
        assert result['majority_resolution'] is None
        assert result['sample_size'] == 0

    def test_filters_none_resolutions(self):
        """None values in resolutions should be filtered out."""
        calc = ConsensusCalculator(min_samples=5)
        resolutions = ['true_positive'] * 10 + [None] * 5 + ['false_positive'] * 2
        
        result = calc.calculate_consensus(resolutions)
        
        assert result['sample_size'] == 12  # Not 17
        assert result['majority_resolution'] == 'true_positive'

    def test_filters_empty_string_resolutions(self):
        """Empty string resolutions should be filtered out."""
        calc = ConsensusCalculator(min_samples=5)
        resolutions = ['true_positive'] * 8 + [''] * 3 + ['false_positive'] * 2
        
        result = calc.calculate_consensus(resolutions)
        
        assert result['sample_size'] == 10  # Not 13

    def test_distribution_included(self):
        """Result should include full distribution counts."""
        calc = ConsensusCalculator(min_samples=5)
        resolutions = ['true_positive'] * 10 + ['false_positive'] * 5 + ['ignored'] * 3
        
        result = calc.calculate_consensus(resolutions)
        
        assert 'distribution' in result
        assert result['distribution']['true_positive'] == 10
        assert result['distribution']['false_positive'] == 5
        assert result['distribution']['ignored'] == 3

    def test_confidence_interval_included(self):
        """Result should include confidence interval."""
        calc = ConsensusCalculator(min_samples=5)
        resolutions = ['true_positive'] * 50
        
        result = calc.calculate_consensus(resolutions)
        
        assert 'confidence_interval' in result
        ci = result['confidence_interval']
        assert len(ci) == 2
        assert 0 <= ci[0] <= ci[1] <= 1

    def test_three_way_split(self):
        """Should handle three-way resolution split."""
        calc = ConsensusCalculator(min_samples=5)
        resolutions = ['true_positive'] * 10 + ['false_positive'] * 8 + ['ignored'] * 7
        
        result = calc.calculate_consensus(resolutions)
        
        assert result['majority_resolution'] == 'true_positive'
        assert result['sample_size'] == 25
        assert result['strength'] == 'weak'

    def test_exact_threshold(self):
        """Edge case: exactly at strong threshold."""
        calc = ConsensusCalculator(min_samples=20, strong_threshold=0.90)
        # 90% with enough samples for tight CI
        resolutions = ['true_positive'] * 90 + ['false_positive'] * 10
        
        result = calc.calculate_consensus(resolutions)
        
        assert result['ratio'] == 0.9
        # Strength depends on CI lower bound


class TestWilsonInterval:
    """Tests for Wilson confidence interval calculation."""

    def test_wilson_interval_perfect_consensus(self):
        """100% agreement should have high lower bound."""
        calc = ConsensusCalculator()
        
        ci_low, ci_high = calc._wilson_interval(100, 100)
        
        assert ci_low > 0.95
        assert ci_high == 1.0

    def test_wilson_interval_zero_successes(self):
        """0% should have low upper bound."""
        calc = ConsensusCalculator()
        
        ci_low, ci_high = calc._wilson_interval(0, 100)
        
        # Use approximate comparison for floating point
        assert ci_low < 0.001  # Essentially zero
        assert ci_high < 0.05

    def test_wilson_interval_small_sample(self):
        """Small samples should have wider intervals."""
        calc = ConsensusCalculator()
        
        ci_small = calc._wilson_interval(9, 10)
        ci_large = calc._wilson_interval(90, 100)
        
        # Same proportion but different sample sizes
        small_width = ci_small[1] - ci_small[0]
        large_width = ci_large[1] - ci_large[0]
        
        assert small_width > large_width

    def test_wilson_interval_n_zero(self):
        """Zero samples should return (0, 0)."""
        calc = ConsensusCalculator()
        
        ci_low, ci_high = calc._wilson_interval(0, 0)
        
        assert ci_low == 0.0
        assert ci_high == 0.0

    def test_wilson_interval_bounds(self):
        """Interval should always be within [0, 1]."""
        calc = ConsensusCalculator()
        
        for successes in [0, 1, 5, 10, 50, 99, 100]:
            ci_low, ci_high = calc._wilson_interval(successes, 100)
            assert 0 <= ci_low <= ci_high <= 1


class TestDetectContradiction:
    """Tests for contradiction detection."""

    def test_no_contradiction_matches_consensus(self, strong_tp_consensus):
        """Resolution matching consensus should not be a contradiction."""
        calc = ConsensusCalculator()
        
        result = calc.detect_contradiction('true_positive', strong_tp_consensus)
        
        assert result['is_contradiction'] is False
        assert result['severity'] is None
        assert result['reason'] == 'matches_consensus'

    def test_critical_fp_contradicts_strong_tp(self, strong_tp_consensus):
        """FP when history is strongly TP should be CRITICAL."""
        calc = ConsensusCalculator()
        
        result = calc.detect_contradiction('false_positive', strong_tp_consensus)
        
        assert result['is_contradiction'] is True
        assert result['severity'] == 'CRITICAL'
        assert 'fp_contradicts_strong_tp' in result['reason']

    def test_high_tp_contradicts_strong_fp(self, strong_fp_consensus):
        """TP when history is strongly FP should be HIGH."""
        calc = ConsensusCalculator()
        
        result = calc.detect_contradiction('true_positive', strong_fp_consensus)
        
        assert result['is_contradiction'] is True
        assert result['severity'] == 'HIGH'
        assert 'tp_contradicts_strong_fp' in result['reason']

    def test_medium_ignored_contradicts_strong_tp(self, strong_tp_consensus):
        """Ignored when history is strongly TP should be MEDIUM."""
        calc = ConsensusCalculator()
        
        result = calc.detect_contradiction('ignored', strong_tp_consensus)
        
        assert result['is_contradiction'] is True
        assert result['severity'] == 'MEDIUM'
        assert 'ignored_contradicts_strong_tp' in result['reason']

    def test_low_contradicts_weak_consensus(self, weak_consensus):
        """Any contradiction of weak consensus should be LOW."""
        calc = ConsensusCalculator()
        
        result = calc.detect_contradiction('false_positive', weak_consensus)
        
        assert result['is_contradiction'] is True
        assert result['severity'] == 'LOW'
        assert 'weak_consensus' in result['reason']

    def test_info_novel_pattern(self, no_data_consensus):
        """No historical data should be INFO (novel pattern)."""
        calc = ConsensusCalculator()
        
        result = calc.detect_contradiction('true_positive', no_data_consensus)
        
        assert result['is_contradiction'] is False
        assert result['severity'] == 'INFO'
        assert result['reason'] == 'novel_pattern'

    def test_info_insufficient_data(self, insufficient_data_consensus):
        """Insufficient historical data should be INFO."""
        calc = ConsensusCalculator()
        
        result = calc.detect_contradiction('false_positive', insufficient_data_consensus)
        
        assert result['is_contradiction'] is False
        assert result['severity'] == 'INFO'
        assert 'insufficient' in result['reason']

    def test_contradiction_includes_details(self, strong_tp_consensus):
        """Contradiction result should include context details."""
        calc = ConsensusCalculator()
        
        result = calc.detect_contradiction('false_positive', strong_tp_consensus)
        
        assert result['new_resolution'] == 'false_positive'
        assert result['historical_resolution'] == 'true_positive'
        assert result['consensus_strength'] == 'strong'
        assert result['sample_size'] == 100
        assert result['historical_ratio'] == 0.95

    def test_tp_contradicts_ignored_is_low(self):
        """TP when history is strongly ignored should be LOW."""
        calc = ConsensusCalculator()
        ignored_consensus = {
            'status': 'consensus',
            'majority_resolution': 'ignored',
            'ratio': 0.92,
            'sample_size': 50,
            'strength': 'strong'
        }
        
        result = calc.detect_contradiction('true_positive', ignored_consensus)
        
        assert result['is_contradiction'] is True
        assert result['severity'] == 'LOW'


class TestContradictionEdgeCases:
    """Edge cases for contradiction detection."""

    def test_unknown_status(self):
        """Unknown consensus status should return INFO."""
        calc = ConsensusCalculator()
        weird_consensus = {'status': 'unknown_status'}
        
        result = calc.detect_contradiction('true_positive', weird_consensus)
        
        assert result['is_contradiction'] is False
        assert result['severity'] == 'INFO'

    def test_missing_status(self):
        """Missing status key should be handled."""
        calc = ConsensusCalculator()
        
        result = calc.detect_contradiction('true_positive', {})
        
        assert result['severity'] == 'INFO'
        assert result['reason'] == 'novel_pattern'

    def test_empty_consensus(self):
        """Empty consensus dict should be handled."""
        calc = ConsensusCalculator()
        
        result = calc.detect_contradiction('true_positive', {})
        
        assert result['is_contradiction'] is False

    def test_moderate_strength_contradiction(self):
        """Moderate strength should also get high severity ratings."""
        calc = ConsensusCalculator()
        moderate_consensus = {
            'status': 'consensus',
            'majority_resolution': 'true_positive',
            'ratio': 0.85,
            'sample_size': 50,
            'strength': 'moderate'
        }
        
        result = calc.detect_contradiction('false_positive', moderate_consensus)
        
        assert result['is_contradiction'] is True
        assert result['severity'] == 'CRITICAL'


class TestIntegration:
    """Integration tests combining consensus calculation and contradiction detection."""

    def test_full_workflow(self):
        """Test complete workflow from resolutions to contradiction detection."""
        calc = ConsensusCalculator(min_samples=20, strong_threshold=0.90)
        
        # Build historical baseline
        historical_resolutions = ['true_positive'] * 95 + ['false_positive'] * 5
        consensus = calc.calculate_consensus(historical_resolutions)
        
        # New alert comes in marked as false_positive
        contradiction = calc.detect_contradiction('false_positive', consensus)
        
        assert contradiction['is_contradiction'] is True
        assert contradiction['severity'] == 'CRITICAL'
        assert contradiction['historical_ratio'] == 0.95

    def test_novel_pattern_workflow(self):
        """Test workflow when no historical data exists."""
        calc = ConsensusCalculator()
        
        consensus = calc.calculate_consensus([])
        contradiction = calc.detect_contradiction('true_positive', consensus)
        
        assert consensus['status'] == 'no_data'
        assert contradiction['reason'] == 'novel_pattern'
        assert contradiction['severity'] == 'INFO'

    def test_growing_baseline(self):
        """Test that consensus strengthens as data grows."""
        calc = ConsensusCalculator(min_samples=10)
        
        # Start with small sample
        small_sample = ['true_positive'] * 9 + ['false_positive'] * 1
        consensus_small = calc.calculate_consensus(small_sample)
        
        # Grow to larger sample
        large_sample = ['true_positive'] * 90 + ['false_positive'] * 10
        consensus_large = calc.calculate_consensus(large_sample)
        
        # Both have 90% ratio but different confidence
        assert consensus_small['ratio'] == consensus_large['ratio']
        ci_small = consensus_small.get('confidence_interval', (0, 0))
        ci_large = consensus_large['confidence_interval']
        
        # Large sample should have tighter interval
        if ci_small != (0, 0):  # If not insufficient data
            assert (ci_large[1] - ci_large[0]) < (ci_small[1] - ci_small[0])