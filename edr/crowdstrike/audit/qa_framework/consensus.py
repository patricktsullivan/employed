# consensus.py

"""
Consensus Calculation and Contradiction Detection

Analyzes historical resolution data to establish consensus and identify
when new resolutions contradict established patterns.

The consensus calculation uses Wilson score confidence intervals to
account for sample size uncertainty. This prevents declaring "strong
consensus" from sparse data (e.g., 9/10 is not as reliable as 900/1000).
"""

from collections import Counter
from scipy import stats

class ConsensusCalculator:
    """
    Calculates historical consensus and detects contradictions.
    
    Consensus strength is determined by:
    1. The ratio of the majority resolution to total resolutions
    2. The lower bound of the Wilson confidence interval
    3. The total sample size
    
    Example:
        >>> calc = ConsensusCalculator(min_samples=20, strong_threshold=0.90)
        >>> resolutions = ['true_positive'] * 45 + ['false_positive'] * 5
        >>> consensus = calc.calculate_consensus(resolutions)
        >>> print(consensus)
        {'status': 'consensus', 'majority_resolution': 'true_positive', 
         'ratio': 0.9, 'sample_size': 50, 'strength': 'strong'}
    """

    def __init__(self, min_samples: int = 20, strong_threshold: float = 0.90):
        self.min_samples = min_samples
        self.strong_threshold = strong_threshold

    def calculate_consensus(self, resolutions: list[str]) -> dict:
        """Calculate consensus from a list of historical resolutions.
        
        Args:
            resolutions: List of resolution strings (true_positive, 
                false_positive, ignored)
                
        Returns:
            Dict with consensus status and details:
            - status: 'consensus', 'insufficient_data', or 'no_data'
            - majority_resolution: Most common resolution (if consensus)
            - ratio: Proportion of majority resolution
            - sample_size: Total number of resolutions
            - strength: 'strong', 'moderate', or 'weak'
        """
        # Filter out None/empty resolutions
        valid_resolutions = [r for r in resolutions if r]
        n = len(valid_resolutions)
        
        if n == 0:
            return {
                'status': 'no_data',
                'majority_resolution': None,
                'ratio': None,
                'sample_size': 0,
                'strength': None
            }
        
        if n < self.min_samples:
            # Still provide the data, but mark as insufficient
            counts = Counter(valid_resolutions)
            majority_resolution, majority_count = counts.most_common(1)[0]
            return {
                'status': 'insufficient_data',
                'majority_resolution': majority_resolution,
                'ratio': majority_count / n,
                'sample_size': n,
                'strength': None
            }
        
        # Calculate majority
        counts = Counter(valid_resolutions)
        majority_resolution, majority_count = counts.most_common(1)[0]
        ratio = majority_count / n
        
        # Calculate Wilson confidence interval
        ci_low, ci_high = self._wilson_interval(majority_count, n)
        
        # Determine strength
        if ratio >= self.strong_threshold and ci_low >= 0.70:
            strength = 'strong'
        elif ratio >= 0.80:
            strength = 'moderate'
        else:
            strength = 'weak'
        
        return {
            'status': 'consensus',
            'majority_resolution': majority_resolution,
            'ratio': round(ratio, 3),
            'sample_size': n,
            'strength': strength,
            'confidence_interval': (round(ci_low, 3), round(ci_high, 3)),
            'distribution': dict(counts)
        }
    
    def _wilson_interval(
        self, 
        successes: int, 
        n: int, 
        confidence: float = 0.95
    ) -> tuple[float, float]:
        """Calculate Wilson score confidence interval.
        
        The Wilson interval is preferred over the normal approximation
        because it:
        - Works well with small samples
        - Never produces intervals outside [0, 1]
        - Handles edge cases (0% or 100%) gracefully
        
        Args:
            successes: Count of "successes" (majority resolution occurrences)
            n: Total sample size
            confidence: Confidence level (default 0.95 for 95% CI)
            
        Returns:
            Tuple of (lower_bound, upper_bound)
        """
        if n == 0:
            return (0.0, 0.0)
        
        z = stats.norm.ppf(1 - (1 - confidence) / 2)
        p = successes / n
        
        denominator = 1 + z**2 / n
        center = (p + z**2 / (2 * n)) / denominator
        spread = z * ((p * (1 - p) / n + z**2 / (4 * n**2)) ** 0.5) / denominator
        
        ci_low = float(max(0, center - spread))
        ci_high = float(min(1, center + spread))

        return (ci_low, ci_high)
    
    def detect_contradiction(
        self, 
        new_resolution: str, 
        consensus: dict
    ) -> dict:
        """Determine if a new resolution contradicts historical consensus.
        
        Severity levels:
        - CRITICAL: New FP when history is strongly TP (potential missed threat)
        - HIGH: New TP when history is strongly FP (potential overreaction)
        - MEDIUM: New Ignored when history is strongly TP (inconsistent priority)
        - LOW: Weak consensus contradiction or less severe combinations
        - INFO: Novel pattern (no historical match)
        
        Args:
            new_resolution: The analyst's resolution for the new alert
            consensus: Dict from calculate_consensus()
            
        Returns:
            Dict with contradiction details:
            - is_contradiction: Boolean
            - severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
            - reason: Explanation of the determination
        """
        status = consensus.get('status', 'no_data')
        
        # Handle non-consensus cases
        if status == 'no_data':
            return {
                'is_contradiction': False,
                'severity': 'INFO',
                'reason': 'novel_pattern'
            }
        
        if status == 'insufficient_data':
            return {
                'is_contradiction': False,
                'severity': 'INFO',
                'reason': 'insufficient_historical_data'
            }
        
        if status != 'consensus':
            return {
                'is_contradiction': False,
                'severity': 'INFO',
                'reason': status
            }
        
        historical = consensus['majority_resolution']
        
        # Check for match
        if new_resolution == historical:
            return {
                'is_contradiction': False,
                'severity': None,
                'reason': 'matches_consensus'
            }
        
        # Contradiction detected - determine severity
        strength = consensus.get('strength', 'weak')
        
        if strength in ('strong', 'moderate'):
            # High-confidence contradictions
            if historical == 'true_positive' and new_resolution == 'false_positive':
                severity = 'CRITICAL'
                reason = 'fp_contradicts_strong_tp_consensus'
            elif historical == 'false_positive' and new_resolution == 'true_positive':
                severity = 'HIGH'
                reason = 'tp_contradicts_strong_fp_consensus'
            elif historical == 'true_positive' and new_resolution == 'ignored':
                severity = 'MEDIUM'
                reason = 'ignored_contradicts_strong_tp_consensus'
            elif historical == 'ignored' and new_resolution == 'true_positive':
                severity = 'LOW'
                reason = 'tp_contradicts_ignored_consensus'
            else:
                severity = 'LOW'
                reason = 'other_contradiction'
        else:
            # Weak consensus - all contradictions are LOW
            severity = 'LOW'
            reason = 'contradicts_weak_consensus'
        
        return {
            'is_contradiction': True,
            'severity': severity,
            'reason': reason,
            'new_resolution': new_resolution,
            'historical_resolution': historical,
            'consensus_strength': strength,
            'sample_size': consensus.get('sample_size', 0),
            'historical_ratio': consensus.get('ratio')
        }