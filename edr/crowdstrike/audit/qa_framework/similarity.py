# similarity.py

"""
Fuzzy template similarity analysis using Jaccard index.

This module provides a secondary matching layer for the QA framework.
While the primary consensus system uses exact hash matching, this module
identifies related patterns that may inform analyst decisions for:
    - Novel alerts with no exact historical match
    - Contradictions where additional context is valuable

The similarity analysis respects the primary grouping constraint: templates
are only compared within the same pattern_id.
"""

import re
from dataclasses import dataclass


@dataclass
class SimilarMatch:
    """A template that is similar but not identical to the query."""
    template_hash: str
    template: str
    similarity: float
    shared_tokens: set[str]
    unique_to_query: set[str]
    unique_to_match: set[str]
    pattern_id: int

class SimilarityAnalyzer:
    """Finds similar templates using Jaccard similarity on token sets."""
    
    def __init__(self, similarity_threshold: float = 0.70):
        """
        Initialize the similarity analyzer.
        
        Args:
            similarity_threshold: Minimum Jaccard score to consider templates
                related. Default 0.70 means at least 70% token overlap.
                Lower values increase recall but may surface less relevant matches.
        """
        if not 0.0 < similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be between 0 and 1")
        
        self.threshold = similarity_threshold
        self._template_tokens: dict[str, set[str]] = {}  # hash -> token set
        self._template_raw: dict[str, str] = {}  # hash -> original template
        self._hash_to_pattern: dict[str, int] = {}  # hash -> pattern_id
        self._pattern_to_hashes: dict[int, set[str]] = {}  # pattern_id -> set of hashes
    
    def tokenize(self, template: str) -> set[str]:
        """Convert sanitized template to token set."""
        # Split on whitespace and common delimiters
        tokens = re.split(r'[\s\\/\-\.\,\;\:\=]+', template.lower())
        # Filter empty tokens and very short ones (noise)
        return {t for t in tokens if len(t) > 1}
    
    def index_template(
        self, 
        template_hash: str, 
        template: str, 
        pattern_id: int
    ) -> None:
        """Add a template to the similarity index."""
        self._template_tokens[template_hash] = self.tokenize(template)
        self._template_raw[template_hash] = template
        self._hash_to_pattern[template_hash] = pattern_id

        # Maintain reverse index for efficient pattern-scoped lookups
        if pattern_id not in self._pattern_to_hashes:
            self._pattern_to_hashes[pattern_id] = set()
        self._pattern_to_hashes[pattern_id].add(template_hash)
    
    def index_count(self) -> int:
        """Return the number of templates in the index."""
        return len(self._template_tokens)
    
    def patterns_indexed(self) -> int:
        """Return the number of unique pattern_ids in the index."""
        return len(self._pattern_to_hashes)

    @staticmethod
    def jaccard_similarity(set_a: set, set_b: set) -> float:
        """
        Calculate Jaccard index between two sets.
        
        Jaccard index = | Intersection of A and B | / | Union of A and B |
        """
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        return intersection / union if union > 0 else 0.0
    
    def find_similar(
        self, 
        template_hash: str, 
        template: str, 
        pattern_id: int,
        max_results: int = 5
    ) -> list[SimilarMatch]:
        """
        Find templates similar to the given one.
        
        Only compares within the same pattern_id to maintain the primary
        grouping constraint. This prevents false associations between
        unrelated detection types.
        
        Args:
            template_hash: Hash of the query template
            template: The sanitized template to find matches for
            pattern_id: CrowdStrike pattern_id (limits comparison scope)
            max_results: Maximum number of matches to return
            
        Returns:
            List of SimilarMatch objects sorted by similarity (descending).
            Only includes matches above the similarity_threshold.
        """
        query_tokens = self.tokenize(template)
        candidates = []
        
        # Get candidate hashes from the same pattern_id only
        candidate_hashes = self._pattern_to_hashes.get(pattern_id, set())
        
        for other_hash in candidate_hashes:
            # Skip self-comparison
            if other_hash == template_hash:
                continue
            
            other_tokens = self._template_tokens[other_hash]
            similarity = self.jaccard_similarity(query_tokens, other_tokens)
            
            if similarity >= self.threshold:
                candidates.append(SimilarMatch(
                    template_hash=other_hash,
                    template=self._template_raw[other_hash],
                    similarity=round(similarity, 3),
                    shared_tokens=query_tokens & other_tokens,
                    unique_to_query=query_tokens - other_tokens,
                    unique_to_match=other_tokens - query_tokens,
                    pattern_id=pattern_id
                ))
        
        # Sort by similarity descending
        candidates.sort(key=lambda x: x.similarity, reverse=True)
        return candidates[:max_results]
    
    def find_similar_batch(
        self,
        queries: list[tuple[str, str, int]],
        max_results_per_query: int = 5
    ) -> dict[str, list[SimilarMatch]]:
        """
        Find similar templates for multiple queries efficiently.
        
        Args:
            queries: List of (template_hash, template, pattern_id) tuples
            max_results_per_query: Maximum matches per query
            
        Returns:
            Dict mapping template_hash to list of SimilarMatch objects
        """
        results = {}
        for template_hash, template, pattern_id in queries:
            results[template_hash] = self.find_similar(
                template_hash, 
                template, 
                pattern_id,
                max_results_per_query
            )
        return results
    
def enrich_qa_finding_with_similarity(
    finding: dict,
    similar_matches: list[SimilarMatch],
    consensus_lookup: dict[str, dict]
) -> dict:
    """
    Add related pattern information to a QA finding.
    
    Enriches a finding dict with consensus data for similar templates,
    giving analysts context about how related patterns were historically
    resolved.
    
    Args:
        finding: The original finding dict from contradiction detection
        similar_matches: List of SimilarMatch objects from find_similar()
        consensus_lookup: Dict mapping template_hash to consensus results
        
    Returns:
        Finding dict with 'related_patterns' key added
    """
    related = []
    
    for match in similar_matches:
        consensus = consensus_lookup.get(match.template_hash, {})
        
        related.append({
            'template_hash': match.template_hash,
            'similarity': match.similarity,
            'historical_consensus': consensus.get('majority_resolution'),
            'sample_size': consensus.get('sample_size', 0),
            'strength': consensus.get('strength'),
            'differentiating_tokens': list(match.unique_to_query | match.unique_to_match),
            'shared_tokens': list(match.shared_tokens)
        })
    
    finding['related_patterns'] = related
    return finding