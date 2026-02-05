"""
Configuration loading for Arbitrary Queries.

Supports loading configuration from JSON and YAML files.
All configuration sections have sensible defaults except for
OnePassword references which must be provided.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when configuration loading or validation fails."""
    pass


@dataclass
class OnePasswordConfig:
    """
    1Password secret references.
    
    Attributes:
        client_id_ref: op:// reference for CrowdStrike client ID.
        client_secret_ref: op:// reference for CrowdStrike client secret.
    """
    
    client_id_ref: str
    client_secret_ref: str


@dataclass
class CrowdStrikeConfig:
    """
    CrowdStrike API configuration.
    
    Attributes:
        base_url: CrowdStrike API base URL (cloud-specific).
        repository: NG-SIEM repository name for queries.
    """
    
    base_url: str = "https://api.laggar.gcw.crowdstrike.com"
    repository: str = "search-all"


@dataclass
class QueryDefaults:
    """
    Default settings for query execution.
    
    Attributes:
        time_range: Default time range for queries (e.g., "-7d").
        poll_interval_seconds: How often to poll for query status.
        timeout_seconds: Maximum time to wait for query completion.
    """
    
    time_range: str = "-7d"
    poll_interval_seconds: int = 60
    timeout_seconds: int = 3600


@dataclass
class ConcurrencyConfig:
    """
    Concurrency and retry settings.
    
    Attributes:
        max_concurrent_queries: Maximum parallel queries.
        retry_attempts: Number of retry attempts on failure.
        retry_delay_seconds: Delay between retry attempts.
    """
    
    max_concurrent_queries: int = 50
    retry_attempts: int = 3
    retry_delay_seconds: int = 5


@dataclass
class Config:
    """
    Complete application configuration.
    
    Attributes:
        onepassword: 1Password secret references.
        crowdstrike: CrowdStrike API settings.
        query_defaults: Default query parameters.
        concurrency: Concurrency and retry settings.
        cid_registry_path: Path to CID registry JSON file.
        queries_dir: Directory containing query files.
        output_dir: Directory for output files.
    """
    
    onepassword: OnePasswordConfig
    crowdstrike: CrowdStrikeConfig = field(default_factory=CrowdStrikeConfig)
    query_defaults: QueryDefaults = field(default_factory=QueryDefaults)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    cid_registry_path: Path = field(default_factory=lambda: Path("./data/cid_registry.json"))
    queries_dir: Path = field(default_factory=lambda: Path("./queries"))
    output_dir: Path = field(default_factory=lambda: Path("./output"))

def _validate_op_reference(ref: str, field_name: str) -> None:
    """Validate that a string looks like a 1Password reference."""
    if not ref or not ref.startswith("op://"):
        raise ConfigError(
            f"Invalid {field_name}: must be a 1Password reference starting with 'op://', got: {ref!r}"
        )

def _parse_config_dict(data: dict[str, Any]) -> Config:
    """
    Parse configuration dictionary into Config object.
    
    Args:
        data: Configuration dictionary.
    
    Returns:
        Parsed Config object.
    
    Raises:
        ConfigError: If required fields are missing.
    """
    # OnePassword config is required
    op_data = data.get("onepassword")
    if not op_data:
        raise ConfigError("Missing required 'onepassword' configuration section")
    
    try:
        onepassword = OnePasswordConfig(
            client_id_ref=op_data["client_id_ref"],
            client_secret_ref=op_data["client_secret_ref"],
        )
    except KeyError as e:
        raise ConfigError(f"Missing required OnePassword field: {e}")
    
    # Validate format of references
    _validate_op_reference(onepassword.client_id_ref, "client_id_ref")
    _validate_op_reference(onepassword.client_secret_ref, "client_secret_ref")

    # CrowdStrike config with defaults
    cs_data = data.get("crowdstrike", {})
    crowdstrike = CrowdStrikeConfig(
        base_url=cs_data.get("base_url", CrowdStrikeConfig.base_url),
        repository=cs_data.get("repository", CrowdStrikeConfig.repository),
    )
    
    # Query defaults
    qd_data = data.get("query_defaults", {})
    query_defaults = QueryDefaults(
        time_range=qd_data.get("time_range", QueryDefaults.time_range),
        poll_interval_seconds=qd_data.get("poll_interval_seconds", QueryDefaults.poll_interval_seconds),
        timeout_seconds=qd_data.get("timeout_seconds", QueryDefaults.timeout_seconds),
    )
    
    # Concurrency config
    cc_data = data.get("concurrency", {})
    concurrency = ConcurrencyConfig(
        max_concurrent_queries=cc_data.get("max_concurrent_queries", ConcurrencyConfig.max_concurrent_queries),
        retry_attempts=cc_data.get("retry_attempts", ConcurrencyConfig.retry_attempts),
        retry_delay_seconds=cc_data.get("retry_delay_seconds", ConcurrencyConfig.retry_delay_seconds),
    )
    
    # Paths
    paths_data = data.get("paths", {})
    cid_registry_path = Path(paths_data.get("cid_registry_path", "./data/cid_registry.json"))
    queries_dir = Path(paths_data.get("queries_dir", "./queries"))
    output_dir = Path(paths_data.get("output_dir", "./output"))
    
    return Config(
        onepassword=onepassword,
        crowdstrike=crowdstrike,
        query_defaults=query_defaults,
        concurrency=concurrency,
        cid_registry_path=cid_registry_path,
        queries_dir=queries_dir,
        output_dir=output_dir,
    )


def load_config_from_json(path: str | Path) -> Config:
    """
    Load configuration from a JSON file.
    
    Args:
        path: Path to JSON configuration file.
    
    Returns:
        Parsed Config object.
    
    Raises:
        ConfigError: If file is missing or invalid.
    """
    path = Path(path)
    
    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")
    
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ConfigError(f"Failed to parse JSON configuration: {e}")
    
    return _parse_config_dict(data)


def load_config_from_yaml(path: str | Path) -> Config:
    """
    Load configuration from a YAML file.
    
    Args:
        path: Path to YAML configuration file.
    
    Returns:
        Parsed Config object.
    
    Raises:
        ConfigError: If file is missing or invalid.
    """
    path = Path(path)
    
    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")
    
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise ConfigError(f"Failed to parse YAML configuration: {e}")
    
    return _parse_config_dict(data)


def load_config(path: str | Path) -> Config:
    """
    Load configuration from file, auto-detecting format by extension.
    
    Supports:
        - .json: JSON format
        - .yaml, .yml: YAML format
    
    Args:
        path: Path to configuration file.
    
    Returns:
        Parsed Config object.
    
    Raises:
        ConfigError: If file format is unsupported or file is invalid.
    """
    path = Path(path)
    suffix = path.suffix.lower()
    
    if suffix == ".json":
        return load_config_from_json(path)
    elif suffix in (".yaml", ".yml"):
        return load_config_from_yaml(path)
    else:
        raise ConfigError(
            f"Unsupported configuration format: {suffix}. "
            "Use .json, .yaml, or .yml"
        )
