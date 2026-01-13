# test_similarity.py

"""
Tests for the SimilarityAnalyzer class and helper functions.

These tests verify that:
1. Jaccard similarity is calculated correctly
2. Templates are tokenized properly
3. Similar templates are found within the same pattern_id only
4. Finding enrichment works correctly
"""

import pytest
from similarity import (
    SimilarityAnalyzer, 
    SimilarMatch, 
    enrich_qa_finding_with_similarity
)


class TestSimilarityAnalyzerInit:
    """Tests for SimilarityAnalyzer initialization."""

    def test_default_threshold(self):
        """Default threshold should be 0.70."""
        analyzer = SimilarityAnalyzer()
        assert analyzer.threshold == 0.70

    def test_custom_threshold(self):
        """Custom threshold should be accepted."""
        analyzer = SimilarityAnalyzer(similarity_threshold=0.80)
        assert analyzer.threshold == 0.80

    def test_invalid_threshold_zero(self):
        """Threshold of 0 should raise ValueError."""
        with pytest.raises(ValueError):
            SimilarityAnalyzer(similarity_threshold=0.0)

    def test_invalid_threshold_negative(self):
        """Negative threshold should raise ValueError."""
        with pytest.raises(ValueError):
            SimilarityAnalyzer(similarity_threshold=-0.5)

    def test_invalid_threshold_above_one(self):
        """Threshold above 1 should raise ValueError."""
        with pytest.raises(ValueError):
            SimilarityAnalyzer(similarity_threshold=1.5)

    def test_threshold_exactly_one(self):
        """Threshold of exactly 1.0 should be valid."""
        analyzer = SimilarityAnalyzer(similarity_threshold=1.0)
        assert analyzer.threshold == 1.0


class TestTokenize:
    """Tests for the tokenize method."""

    def test_tokenize_basic(self):
        """Basic command should be tokenized correctly."""
        analyzer = SimilarityAnalyzer()
        
        tokens = analyzer.tokenize("powershell.exe -enc bypass")
        
        assert 'powershell' in tokens
        assert 'exe' in tokens
        assert 'enc' in tokens
        assert 'bypass' in tokens

    def test_tokenize_removes_short_tokens(self):
        """Single-character tokens should be removed."""
        analyzer = SimilarityAnalyzer()
        
        tokens = analyzer.tokenize("cmd /c echo a b c")
        
        assert 'a' not in tokens
        assert 'b' not in tokens
        assert 'c' not in tokens
        assert 'cmd' in tokens

    def test_tokenize_case_insensitive(self):
        """Tokenization should be case-insensitive."""
        analyzer = SimilarityAnalyzer()
        
        tokens1 = analyzer.tokenize("PowerShell.EXE")
        tokens2 = analyzer.tokenize("powershell.exe")
        
        assert tokens1 == tokens2

    def test_tokenize_splits_on_delimiters(self):
        """Should split on various delimiters."""
        analyzer = SimilarityAnalyzer()
        
        tokens = analyzer.tokenize(r"C:\Windows\System32\cmd.exe")
        
        assert 'windows' in tokens
        assert 'system32' in tokens
        assert 'cmd' in tokens

    def test_tokenize_template_format(self):
        """Should handle full template format.
        
        Note: The tokenizer splits on specific delimiters (whitespace, 
        backslash, hyphen, period, comma, semicolon, colon, equals).
        Pipe (|) is NOT a delimiter, so tokens may include pipe-joined values.
        """
        analyzer = SimilarityAnalyzer()
        
        template = "pattern:50007|cmd:powershell bypass|file:ps.exe|parent:cmd.exe"
        tokens = analyzer.tokenize(template)
        
        # 'powershell' should be a separate token (split by colon and space)
        assert 'powershell' in tokens
        # 'pattern' is split by colon
        assert 'pattern' in tokens
        # Pipe is not a delimiter, so we may see combined tokens
        # The key thing is meaningful words are extracted

    def test_tokenize_empty_string(self):
        """Empty string should return empty set."""
        analyzer = SimilarityAnalyzer()
        
        tokens = analyzer.tokenize("")
        
        assert tokens == set()


class TestJaccardSimilarity:
    """Tests for static Jaccard similarity calculation."""

    def test_identical_sets(self):
        """Identical sets should have similarity 1.0."""
        result = SimilarityAnalyzer.jaccard_similarity(
            {'a', 'b', 'c'}, 
            {'a', 'b', 'c'}
        )
        assert result == 1.0

    def test_completely_different_sets(self):
        """Completely different sets should have similarity 0.0."""
        result = SimilarityAnalyzer.jaccard_similarity(
            {'a', 'b', 'c'}, 
            {'x', 'y', 'z'}
        )
        assert result == 0.0

    def test_partial_overlap(self):
        """50% overlap should return ~0.33 (2 shared / 6 total)."""
        result = SimilarityAnalyzer.jaccard_similarity(
            {'a', 'b', 'c', 'd'}, 
            {'c', 'd', 'e', 'f'}
        )
        # Intersection: {c, d} = 2
        # Union: {a, b, c, d, e, f} = 6
        # Jaccard = 2/6 = 0.333...
        assert abs(result - 0.333) < 0.01

    def test_empty_set_a(self):
        """Empty first set should return 0.0."""
        result = SimilarityAnalyzer.jaccard_similarity(
            set(), 
            {'a', 'b', 'c'}
        )
        assert result == 0.0

    def test_empty_set_b(self):
        """Empty second set should return 0.0."""
        result = SimilarityAnalyzer.jaccard_similarity(
            {'a', 'b', 'c'}, 
            set()
        )
        assert result == 0.0

    def test_both_empty(self):
        """Both empty sets should return 0.0."""
        result = SimilarityAnalyzer.jaccard_similarity(set(), set())
        assert result == 0.0

    def test_subset(self):
        """Subset relationship should be calculated correctly."""
        result = SimilarityAnalyzer.jaccard_similarity(
            {'a', 'b'}, 
            {'a', 'b', 'c', 'd'}
        )
        # Intersection: {a, b} = 2
        # Union: {a, b, c, d} = 4
        # Jaccard = 2/4 = 0.5
        assert result == 0.5


class TestIndexTemplate:
    """Tests for indexing templates."""

    def test_index_single_template(self):
        """Single template should be indexed correctly."""
        analyzer = SimilarityAnalyzer()
        
        analyzer.index_template('hash1', 'pattern:50007|cmd:test', 50007)
        
        assert analyzer.index_count() == 1
        assert analyzer.patterns_indexed() == 1

    def test_index_multiple_templates_same_pattern(self):
        """Multiple templates with same pattern_id should be indexed."""
        analyzer = SimilarityAnalyzer()
        
        analyzer.index_template('hash1', 'pattern:50007|cmd:test1', 50007)
        analyzer.index_template('hash2', 'pattern:50007|cmd:test2', 50007)
        
        assert analyzer.index_count() == 2
        assert analyzer.patterns_indexed() == 1

    def test_index_multiple_patterns(self):
        """Templates from different patterns should be separate."""
        analyzer = SimilarityAnalyzer()
        
        analyzer.index_template('hash1', 'pattern:50007|cmd:test1', 50007)
        analyzer.index_template('hash2', 'pattern:50102|cmd:test2', 50102)
        
        assert analyzer.index_count() == 2
        assert analyzer.patterns_indexed() == 2


class TestFindSimilar:
    """Tests for finding similar templates."""

    def test_find_similar_basic(self, sample_templates):
        """Should find similar templates within same pattern_id."""
        analyzer = SimilarityAnalyzer(similarity_threshold=0.50)
        
        # Index templates
        for t in sample_templates:
            analyzer.index_template(t['hash'], t['template'], t['pattern_id'])
        
        # Search for similar to first template
        results = analyzer.find_similar(
            'hash_001',
            sample_templates[0]['template'],
            50007
        )
        
        # Should find hash_002 and hash_003 (same pattern_id)
        assert len(results) > 0
        result_hashes = [r.template_hash for r in results]
        assert 'hash_001' not in result_hashes  # No self-match

    def test_find_similar_respects_pattern_boundary(self, sample_templates):
        """Should not find templates from different pattern_ids."""
        analyzer = SimilarityAnalyzer(similarity_threshold=0.10)  # Very low threshold
        
        for t in sample_templates:
            analyzer.index_template(t['hash'], t['template'], t['pattern_id'])
        
        # Search pattern 50007 template
        results = analyzer.find_similar(
            'hash_001',
            sample_templates[0]['template'],
            50007
        )
        
        # Should not include hash_004 or hash_005 (pattern 50102)
        result_hashes = [r.template_hash for r in results]
        assert 'hash_004' not in result_hashes
        assert 'hash_005' not in result_hashes

    def test_find_similar_excludes_self(self):
        """Should not return the query template itself."""
        analyzer = SimilarityAnalyzer(similarity_threshold=0.50)
        
        analyzer.index_template('hash1', 'pattern:50007|cmd:test', 50007)
        
        results = analyzer.find_similar('hash1', 'pattern:50007|cmd:test', 50007)
        
        assert len(results) == 0

    def test_find_similar_respects_threshold(self):
        """Should only return matches above threshold."""
        analyzer = SimilarityAnalyzer(similarity_threshold=0.90)
        
        analyzer.index_template('hash1', 'powershell bypass encoded', 50007)
        analyzer.index_template('hash2', 'powershell bypass hidden', 50007)  # Similar
        analyzer.index_template('hash3', 'cmd echo something else', 50007)  # Different
        
        results = analyzer.find_similar('hash1', 'powershell bypass encoded', 50007)
        
        # High threshold should exclude the dissimilar one
        result_hashes = [r.template_hash for r in results]
        # hash3 should not match due to high threshold
        for match in results:
            assert match.similarity >= 0.90

    def test_find_similar_max_results(self, sample_templates):
        """Should respect max_results parameter."""
        analyzer = SimilarityAnalyzer(similarity_threshold=0.10)
        
        for t in sample_templates:
            analyzer.index_template(t['hash'], t['template'], t['pattern_id'])
        
        results = analyzer.find_similar(
            'hash_001',
            sample_templates[0]['template'],
            50007,
            max_results=1
        )
        
        assert len(results) <= 1

    def test_find_similar_sorted_by_similarity(self):
        """Results should be sorted by similarity descending."""
        analyzer = SimilarityAnalyzer(similarity_threshold=0.10)
        
        analyzer.index_template('query', 'powershell bypass encoded data', 50007)
        analyzer.index_template('high', 'powershell bypass encoded test', 50007)
        analyzer.index_template('medium', 'powershell bypass something else', 50007)
        analyzer.index_template('low', 'cmd echo different command', 50007)
        
        results = analyzer.find_similar('query', 'powershell bypass encoded data', 50007)
        
        if len(results) >= 2:
            for i in range(len(results) - 1):
                assert results[i].similarity >= results[i + 1].similarity

    def test_find_similar_includes_token_diff(self):
        """SimilarMatch should include token differences."""
        analyzer = SimilarityAnalyzer(similarity_threshold=0.50)
        
        analyzer.index_template('hash1', 'powershell bypass encoded', 50007)
        analyzer.index_template('hash2', 'powershell bypass hidden', 50007)
        
        results = analyzer.find_similar('hash1', 'powershell bypass encoded', 50007)
        
        if results:
            match = results[0]
            assert isinstance(match.shared_tokens, set)
            assert isinstance(match.unique_to_query, set)
            assert isinstance(match.unique_to_match, set)
            assert 'powershell' in match.shared_tokens or 'bypass' in match.shared_tokens

    def test_find_similar_empty_pattern(self):
        """Should return empty list for pattern with no templates."""
        analyzer = SimilarityAnalyzer()
        
        analyzer.index_template('hash1', 'test', 50007)
        
        results = analyzer.find_similar('query', 'test', 99999)  # Different pattern
        
        assert results == []


class TestFindSimilarBatch:
    """Tests for batch similarity searching."""

    def test_batch_search(self, sample_templates):
        """Should process multiple queries efficiently."""
        analyzer = SimilarityAnalyzer(similarity_threshold=0.50)
        
        for t in sample_templates:
            analyzer.index_template(t['hash'], t['template'], t['pattern_id'])
        
        queries = [
            ('hash_001', sample_templates[0]['template'], 50007),
            ('hash_004', sample_templates[3]['template'], 50102),
        ]
        
        results = analyzer.find_similar_batch(queries, max_results_per_query=3)
        
        assert 'hash_001' in results
        assert 'hash_004' in results

    def test_batch_empty_queries(self):
        """Empty query list should return empty dict."""
        analyzer = SimilarityAnalyzer()
        
        results = analyzer.find_similar_batch([])
        
        assert results == {}


class TestEnrichQAFinding:
    """Tests for enriching findings with similarity data."""

    def test_enrich_basic(self):
        """Should add related_patterns to finding."""
        finding = {
            'alert_id': 'test-123',
            'severity': 'HIGH'
        }
        
        similar_matches = [
            SimilarMatch(
                template_hash='hash_similar',
                template='test template',
                similarity=0.85,
                shared_tokens={'powershell', 'bypass'},
                unique_to_query={'encoded'},
                unique_to_match={'hidden'},
                pattern_id=50007
            )
        ]
        
        consensus_lookup = {
            'hash_similar': {
                'status': 'consensus',
                'majority_resolution': 'true_positive',
                'sample_size': 50,
                'strength': 'strong'
            }
        }
        
        result = enrich_qa_finding_with_similarity(finding, similar_matches, consensus_lookup)
        
        assert 'related_patterns' in result
        assert len(result['related_patterns']) == 1
        related = result['related_patterns'][0]
        assert related['template_hash'] == 'hash_similar'
        assert related['similarity'] == 0.85
        assert related['historical_consensus'] == 'true_positive'
        assert related['sample_size'] == 50

    def test_enrich_empty_matches(self):
        """Empty similar matches should result in empty related_patterns."""
        finding = {'alert_id': 'test-123'}
        
        result = enrich_qa_finding_with_similarity(finding, [], {})
        
        assert result['related_patterns'] == []

    def test_enrich_missing_consensus(self):
        """Missing consensus data should be handled gracefully."""
        finding = {'alert_id': 'test-123'}
        
        similar_matches = [
            SimilarMatch(
                template_hash='hash_no_consensus',
                template='test',
                similarity=0.75,
                shared_tokens=set(),
                unique_to_query=set(),
                unique_to_match=set(),
                pattern_id=50007
            )
        ]
        
        result = enrich_qa_finding_with_similarity(finding, similar_matches, {})
        
        related = result['related_patterns'][0]
        assert related['historical_consensus'] is None
        assert related['sample_size'] == 0
        assert related['strength'] is None

    def test_enrich_includes_differentiating_tokens(self):
        """Should include tokens that differentiate templates."""
        finding = {'alert_id': 'test-123'}
        
        similar_matches = [
            SimilarMatch(
                template_hash='hash1',
                template='test',
                similarity=0.80,
                shared_tokens={'powershell'},
                unique_to_query={'encoded'},
                unique_to_match={'hidden'},
                pattern_id=50007
            )
        ]
        
        result = enrich_qa_finding_with_similarity(finding, similar_matches, {})
        
        related = result['related_patterns'][0]
        assert 'encoded' in related['differentiating_tokens'] or 'hidden' in related['differentiating_tokens']
        assert 'powershell' in related['shared_tokens']


class TestSimilarMatchDataclass:
    """Tests for the SimilarMatch dataclass."""

    def test_dataclass_creation(self):
        """Should create SimilarMatch with all fields."""
        match = SimilarMatch(
            template_hash='abc123',
            template='test template',
            similarity=0.75,
            shared_tokens={'a', 'b'},
            unique_to_query={'c'},
            unique_to_match={'d'},
            pattern_id=50007
        )
        
        assert match.template_hash == 'abc123'
        assert match.similarity == 0.75
        assert match.pattern_id == 50007

    def test_dataclass_equality(self):
        """Two SimilarMatches with same values should be equal."""
        match1 = SimilarMatch('h1', 't1', 0.5, set(), set(), set(), 1)
        match2 = SimilarMatch('h1', 't1', 0.5, set(), set(), set(), 1)
        
        assert match1 == match2


class TestIntegration:
    """Integration tests for similarity analysis workflow."""

    def test_full_workflow(self):
        """Test indexing, searching, and enrichment together."""
        analyzer = SimilarityAnalyzer(similarity_threshold=0.60)
        
        # Index historical templates
        templates = [
            ('h1', 'powershell encoded bypass execution', 50007),
            ('h2', 'powershell encoded hidden execution', 50007),
            ('h3', 'powershell encoded bypass noprofile', 50007),
            ('h4', 'cmd echo totally different', 50007),
        ]
        
        for hash_val, template, pattern in templates:
            analyzer.index_template(hash_val, template, pattern)
        
        # New alert comes in
        new_hash = 'new_alert'
        new_template = 'powershell encoded bypass download'
        new_pattern = 50007
        
        # Find similar
        similar = analyzer.find_similar(new_hash, new_template, new_pattern)
        
        # Should find h1 and h3 (both have "encoded bypass")
        assert len(similar) >= 1
        
        # Enrich finding
        finding = {'alert_id': 'new_alert', 'severity': 'INFO'}
        consensus_lookup = {
            'h1': {'majority_resolution': 'true_positive', 'sample_size': 30, 'strength': 'moderate'},
            'h3': {'majority_resolution': 'true_positive', 'sample_size': 25, 'strength': 'moderate'},
        }
        
        enriched = enrich_qa_finding_with_similarity(finding, similar, consensus_lookup)
        
        assert 'related_patterns' in enriched
        assert len(enriched['related_patterns']) >= 1