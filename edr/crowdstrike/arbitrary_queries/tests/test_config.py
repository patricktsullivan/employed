"""
Tests for arbitrary_queries.config module.

Tests configuration loading from JSON, YAML, and Python files.
"""

import pytest
import json
import tempfile
from pathlib import Path

from arbitrary_queries.config import (
    Config,
    CrowdStrikeConfig,
    OnePasswordConfig,
    QueryDefaults,
    ConcurrencyConfig,
    load_config,
    load_config_from_json,
    load_config_from_yaml,
    ConfigError,
)


@pytest.fixture
def sample_config_dict():
    """Sample configuration dictionary."""
    return {
        "onepassword": {
            "client_id_ref": "op://Vault/CrowdStrike/client_id",
            "client_secret_ref": "op://Vault/CrowdStrike/client_secret",
        },
        "crowdstrike": {
            "base_url": "https://api.laggar.gcw.crowdstrike.com",
            "repository": "search-all",
        },
        "query_defaults": {
            "time_range": "-7d",
            "poll_interval_seconds": 60,
            "timeout_seconds": 3600,
        },
        "concurrency": {
            "max_concurrent_queries": 50,
            "retry_attempts": 3,
            "retry_delay_seconds": 5,
        },
        "paths": {
            "cid_registry": "./data/cid_registry.json",
            "queries_dir": "./queries",
            "output_dir": "./output",
        },
    }


@pytest.fixture
def sample_json_config_file(sample_config_dict, tmp_path):
    """Create a temporary JSON config file."""
    config_file = tmp_path / "settings.json"
    config_file.write_text(json.dumps(sample_config_dict, indent=2))
    return config_file


@pytest.fixture
def sample_yaml_config_file(sample_config_dict, tmp_path):
    """Create a temporary YAML config file."""
    import yaml
    config_file = tmp_path / "settings.yaml"
    config_file.write_text(yaml.dump(sample_config_dict))
    return config_file


class TestOnePasswordConfig:
    """Tests for OnePasswordConfig data class."""

    def test_create_onepassword_config(self):
        """OnePasswordConfig should store 1Password references."""
        config = OnePasswordConfig(
            client_id_ref="op://Vault/Item/client_id",
            client_secret_ref="op://Vault/Item/client_secret",
        )
        
        assert config.client_id_ref == "op://Vault/Item/client_id"
        assert config.client_secret_ref == "op://Vault/Item/client_secret"


class TestCrowdStrikeConfig:
    """Tests for CrowdStrikeConfig data class."""

    def test_create_crowdstrike_config(self):
        """CrowdStrikeConfig should store API settings."""
        config = CrowdStrikeConfig(
            base_url="https://api.laggar.gcw.crowdstrike.com",
            repository="search-all",
        )
        
        assert config.base_url == "https://api.laggar.gcw.crowdstrike.com"
        assert config.repository == "search-all"

    def test_crowdstrike_config_defaults(self):
        """CrowdStrikeConfig should have sensible defaults."""
        config = CrowdStrikeConfig()
        
        assert config.base_url == "https://api.laggar.gcw.crowdstrike.com"
        assert config.repository == "search-all"


class TestQueryDefaults:
    """Tests for QueryDefaults data class."""

    def test_create_query_defaults(self):
        """QueryDefaults should store query settings."""
        config = QueryDefaults(
            time_range="-7d",
            poll_interval_seconds=60,
            timeout_seconds=3600,
        )
        
        assert config.time_range == "-7d"
        assert config.poll_interval_seconds == 60
        assert config.timeout_seconds == 3600

    def test_query_defaults_defaults(self):
        """QueryDefaults should have sensible defaults."""
        config = QueryDefaults()
        
        assert config.time_range == "-7d"
        assert config.poll_interval_seconds == 60
        assert config.timeout_seconds == 3600


class TestConcurrencyConfig:
    """Tests for ConcurrencyConfig data class."""

    def test_create_concurrency_config(self):
        """ConcurrencyConfig should store concurrency settings."""
        config = ConcurrencyConfig(
            max_concurrent_queries=100,
            retry_attempts=5,
            retry_delay_seconds=10,
        )
        
        assert config.max_concurrent_queries == 100
        assert config.retry_attempts == 5
        assert config.retry_delay_seconds == 10

    def test_concurrency_config_defaults(self):
        """ConcurrencyConfig should have sensible defaults."""
        config = ConcurrencyConfig()
        
        assert config.max_concurrent_queries == 50
        assert config.retry_attempts == 3
        assert config.retry_delay_seconds == 5


class TestConfig:
    """Tests for Config data class."""

    def test_create_config(self):
        """Config should combine all configuration sections."""
        config = Config(
            onepassword=OnePasswordConfig(
                client_id_ref="op://V/I/id",
                client_secret_ref="op://V/I/secret",
            ),
            crowdstrike=CrowdStrikeConfig(),
            query_defaults=QueryDefaults(),
            concurrency=ConcurrencyConfig(),
            cid_registry_path=Path("./data/cid_registry.json"),
            queries_dir=Path("./queries"),
            output_dir=Path("./output"),
        )
        
        assert config.onepassword.client_id_ref == "op://V/I/id"
        assert config.crowdstrike.base_url == "https://api.laggar.gcw.crowdstrike.com"
        assert config.cid_registry_path == Path("./data/cid_registry.json")


class TestLoadConfigFromJson:
    """Tests for load_config_from_json function."""

    def test_load_valid_json_config(self, sample_json_config_file):
        """load_config_from_json should parse valid JSON config."""
        config = load_config_from_json(sample_json_config_file)
        
        assert config.onepassword.client_id_ref == "op://Vault/CrowdStrike/client_id"
        assert config.crowdstrike.base_url == "https://api.laggar.gcw.crowdstrike.com"
        assert config.query_defaults.time_range == "-7d"
        assert config.concurrency.max_concurrent_queries == 50

    def test_load_json_config_with_path_string(self, sample_json_config_file):
        """load_config_from_json should accept path as string."""
        config = load_config_from_json(str(sample_json_config_file))
        
        assert config.onepassword.client_id_ref == "op://Vault/CrowdStrike/client_id"

    def test_load_json_config_missing_file(self, tmp_path):
        """load_config_from_json should raise ConfigError for missing file."""
        missing_file = tmp_path / "nonexistent.json"
        
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_json(missing_file)
        
        assert "not found" in str(exc_info.value).lower()

    def test_load_json_config_invalid_json(self, tmp_path):
        """load_config_from_json should raise ConfigError for invalid JSON."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ invalid json }")
        
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_json(bad_file)
        
        assert "parse" in str(exc_info.value).lower() or "json" in str(exc_info.value).lower()

    def test_load_json_config_uses_defaults(self, tmp_path):
        """load_config_from_json should use defaults for missing optional fields."""
        minimal_config = {
            "onepassword": {
                "client_id_ref": "op://V/I/id",
                "client_secret_ref": "op://V/I/secret",
            },
        }
        config_file = tmp_path / "minimal.json"
        config_file.write_text(json.dumps(minimal_config))
        
        config = load_config_from_json(config_file)
        
        # Should use defaults
        assert config.crowdstrike.base_url == "https://api.laggar.gcw.crowdstrike.com"
        assert config.query_defaults.time_range == "-7d"
        assert config.concurrency.max_concurrent_queries == 50


class TestLoadConfigFromYaml:
    """Tests for load_config_from_yaml function."""

    def test_load_valid_yaml_config(self, sample_yaml_config_file):
        """load_config_from_yaml should parse valid YAML config."""
        config = load_config_from_yaml(sample_yaml_config_file)
        
        assert config.onepassword.client_id_ref == "op://Vault/CrowdStrike/client_id"
        assert config.crowdstrike.repository == "search-all"

    def test_load_yaml_config_missing_file(self, tmp_path):
        """load_config_from_yaml should raise ConfigError for missing file."""
        missing_file = tmp_path / "nonexistent.yaml"
        
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_yaml(missing_file)
        
        assert "not found" in str(exc_info.value).lower()


class TestLoadConfig:
    """Tests for load_config function (auto-detect format)."""

    def test_load_config_detects_json(self, sample_json_config_file):
        """load_config should auto-detect JSON format."""
        config = load_config(sample_json_config_file)
        
        assert config.onepassword.client_id_ref == "op://Vault/CrowdStrike/client_id"

    def test_load_config_detects_yaml(self, sample_yaml_config_file):
        """load_config should auto-detect YAML format."""
        config = load_config(sample_yaml_config_file)
        
        assert config.onepassword.client_id_ref == "op://Vault/CrowdStrike/client_id"

    def test_load_config_detects_yml_extension(self, sample_config_dict, tmp_path):
        """load_config should handle .yml extension."""
        import yaml
        config_file = tmp_path / "settings.yml"
        config_file.write_text(yaml.dump(sample_config_dict))
        
        config = load_config(config_file)
        
        assert config.onepassword.client_id_ref == "op://Vault/CrowdStrike/client_id"

    def test_load_config_unknown_extension(self, tmp_path):
        """load_config should raise ConfigError for unknown extensions."""
        unknown_file = tmp_path / "settings.toml"
        unknown_file.write_text("key = 'value'")
        
        with pytest.raises(ConfigError) as exc_info:
            load_config(unknown_file)
        
        assert "unsupported" in str(exc_info.value).lower() or "format" in str(exc_info.value).lower()
