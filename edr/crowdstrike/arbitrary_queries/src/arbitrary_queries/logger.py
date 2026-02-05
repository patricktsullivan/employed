"""
Logging module for arbitrary-queries.

Provides structured logging with support for:
- Multi-tenant context (CID tracking)
- Query execution tracking
- JSON and human-readable output formats
- Console and file handlers
- Async-friendly context management
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# Context variables for structured logging
_cid_context: ContextVar[str | None] = ContextVar("cid", default=None)
_query_id_context: ContextVar[str | None] = ContextVar("query_id", default=None)
_customer_name_context: ContextVar[str | None] = ContextVar("customer_name", default=None)


class LogFormat(Enum):
    """Log output format options."""
    
    TEXT = "text"
    JSON = "json"


class LogLevel(Enum):
    """Log level options with numeric values."""
    
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


@dataclass
class LogConfig:
    """Configuration for the logging system.
    
    Attributes:
        level: Minimum log level to output.
        format: Output format (text or JSON).
        log_file: Optional file path for log output.
        include_timestamp: Whether to include timestamps.
        include_context: Whether to include CID/query context.
        colorize: Whether to colorize console output (text format only).
    """
    
    level: LogLevel = LogLevel.INFO
    format: LogFormat = LogFormat.TEXT
    log_file: Path | None = None
    include_timestamp: bool = True
    include_context: bool = True
    colorize: bool = True


class LoggingError(Exception):
    """Raised when logging configuration or operations fail."""
    pass


class _Colors:
    """ANSI color codes for terminal output."""
    
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"


_LEVEL_COLORS = {
    logging.DEBUG: _Colors.GRAY,
    logging.INFO: _Colors.GREEN,
    logging.WARNING: _Colors.YELLOW,
    logging.ERROR: _Colors.RED,
    logging.CRITICAL: f"{_Colors.BOLD}{_Colors.RED}",
}


class ContextFormatter(logging.Formatter):
    """Custom formatter that includes context variables."""
    
    def __init__(
        self,
        include_timestamp: bool = True,
        include_context: bool = True,
        colorize: bool = False,
    ):
        self.include_timestamp = include_timestamp
        self.include_context = include_context
        self.colorize = colorize
        super().__init__()
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with context information."""
        parts = []
        
        # Timestamp
        if self.include_timestamp:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            if self.colorize:
                parts.append(f"{_Colors.GRAY}{timestamp}{_Colors.RESET}")
            else:
                parts.append(timestamp)
        
        # Level
        level_name = record.levelname.ljust(8)
        if self.colorize:
            color = _LEVEL_COLORS.get(record.levelno, "")
            parts.append(f"{color}{level_name}{_Colors.RESET}")
        else:
            parts.append(level_name)
        
        # Context (CID, query_id, customer)
        if self.include_context:
            context_parts = []
            
            cid = _cid_context.get()
            if cid:
                cid_short = cid[:8] if len(cid) > 8 else cid
                context_parts.append(f"cid={cid_short}")
            
            query_id = _query_id_context.get()
            if query_id:
                context_parts.append(f"qid={query_id[:8]}")
            
            customer = _customer_name_context.get()
            if customer:
                context_parts.append(f"customer={customer}")
            
            if context_parts:
                context_str = " ".join(context_parts)
                if self.colorize:
                    parts.append(f"{_Colors.CYAN}[{context_str}]{_Colors.RESET}")
                else:
                    parts.append(f"[{context_str}]")
        
        # Module/logger name
        if self.colorize:
            parts.append(f"{_Colors.MAGENTA}{record.name}{_Colors.RESET}")
        else:
            parts.append(record.name)
        
        # Message
        parts.append(record.getMessage())
        
        # Exception info
        if record.exc_info:
            parts.append(self.formatException(record.exc_info))
        
        return " ".join(parts)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured log output."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add context
        cid = _cid_context.get()
        if cid:
            log_data["cid"] = cid
        
        query_id = _query_id_context.get()
        if query_id:
            log_data["query_id"] = query_id
        
        customer = _customer_name_context.get()
        if customer:
            log_data["customer_name"] = customer
        
        # Add extra fields
        extra_data = getattr(record, "extra_data", None)
        if extra_data is not None:
            log_data["data"] = extra_data
        
        # Add exception info
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add source location for debug
        if record.levelno == logging.DEBUG:
            log_data["location"] = {
                "file": record.filename,
                "line": record.lineno,
                "function": record.funcName,
            }
        
        return json.dumps(log_data, default=str)


class LogContext:
    """Context manager for adding logging context.
    
    Usage:
        with LogContext(cid="abc123", customer_name="Acme Corp"):
            logger.info("Processing query")  # Includes CID context
    """
    
    def __init__(
        self,
        cid: str | None = None,
        query_id: str | None = None,
        customer_name: str | None = None,
    ):
        self.cid = cid
        self.query_id = query_id
        self.customer_name = customer_name
        self._tokens: list = []
    
    def __enter__(self) -> LogContext:
        if self.cid is not None:
            self._tokens.append(("cid", _cid_context.set(self.cid)))
        if self.query_id is not None:
            self._tokens.append(("query_id", _query_id_context.set(self.query_id)))
        if self.customer_name is not None:
            self._tokens.append(("customer", _customer_name_context.set(self.customer_name)))
        return self
    
    def __exit__(self, *args) -> None:
        for context_name, token in self._tokens:
            if context_name == "cid":
                _cid_context.reset(token)
            elif context_name == "query_id":
                _query_id_context.reset(token)
            elif context_name == "customer":
                _customer_name_context.reset(token)


class QueryLogger:
    """Specialized logger for query operations.
    
    Provides convenience methods for common query logging patterns.
    """
    
    def __init__(self, logger: logging.Logger):
        self._logger = logger
    
    def query_started(
        self,
        query_name: str,
        cid: str | None = None,
        time_range: str | None = None,
    ) -> None:
        """Log query execution start."""
        msg = f"Starting query: {query_name}"
        if time_range:
            msg += f" (range: {time_range})"
        
        with LogContext(cid=cid):
            self._logger.info(msg)
    
    def query_completed(
        self,
        query_name: str,
        cid: str | None = None,
        event_count: int = 0,
        duration_seconds: float = 0,
    ) -> None:
        """Log successful query completion."""
        msg = f"Query completed: {query_name} ({event_count} events in {duration_seconds:.2f}s)"
        
        with LogContext(cid=cid):
            self._logger.info(msg)
    
    def query_failed(
        self,
        query_name: str,
        error: str | Exception,
        cid: str | None = None,
    ) -> None:
        """Log query failure."""
        error_msg = str(error)
        msg = f"Query failed: {query_name} - {error_msg}"
        
        with LogContext(cid=cid):
            self._logger.error(msg)
    
    def query_polling(
        self,
        query_id: str,
        status: str,
        progress: float | None = None,
    ) -> None:
        """Log query polling status."""
        msg = f"Polling query {query_id[:8]}... status={status}"
        if progress is not None:
            msg += f" ({progress:.0%})"
        
        with LogContext(query_id=query_id):
            self._logger.debug(msg)
    
    def rate_limited(self, retry_after: float) -> None:
        """Log rate limit hit."""
        self._logger.warning(f"Rate limited, retrying after {retry_after:.1f}s")
    
    def retry_attempt(self, attempt: int, max_attempts: int, reason: str) -> None:
        """Log retry attempt."""
        self._logger.warning(f"Retry {attempt}/{max_attempts}: {reason}")


# Module-level logger instance
_root_logger: logging.Logger | None = None
_query_logger: QueryLogger | None = None


def setup_logging(config: LogConfig | None = None) -> logging.Logger:
    """Initialize the logging system.
    
    Args:
        config: Logging configuration. Uses defaults if not provided.
    
    Returns:
        Configured root logger for arbitrary-queries.
    
    Raises:
        LoggingError: If logging setup fails.
    """
    global _root_logger, _query_logger
    
    if config is None:
        config = LogConfig()
    
    # Create logger
    logger = logging.getLogger("arbitrary_queries")
    logger.setLevel(config.level.value)
    logger.handlers.clear()
    
    # Create formatter
    if config.format == LogFormat.JSON:
        formatter = JSONFormatter()
    else:
        # Check if stdout supports colors
        supports_color = (
            config.colorize
            and hasattr(sys.stdout, "isatty")
            and sys.stdout.isatty()
        )
        formatter = ContextFormatter(
            include_timestamp=config.include_timestamp,
            include_context=config.include_context,
            colorize=supports_color,
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if configured)
    if config.log_file:
        try:
            config.log_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Always use JSON for file output (better for parsing)
            file_formatter = JSONFormatter()
            file_handler = logging.FileHandler(config.log_file, encoding="utf-8")
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except (OSError, PermissionError) as e:
            raise LoggingError(f"Failed to create log file: {e}") from e
    
    _root_logger = logger
    _query_logger = QueryLogger(logger)
    
    logger.debug(f"Logging initialized (level={config.level.name}, format={config.format.value})")
    
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a logger instance.
    
    Args:
        name: Logger name. If None, returns the root arbitrary-queries logger.
              If provided, returns a child logger (e.g., "arbitrary_queries.client").
    
    Returns:
        Logger instance.
    """
    global _root_logger
    
    if _root_logger is None:
        setup_logging()
    
    assert _root_logger is not None  # setup_logging always sets this
    
    if name is None:
        return _root_logger
    
    return logging.getLogger(f"arbitrary_queries.{name}")


def get_query_logger() -> QueryLogger:
    """Get the specialized query logger.
    
    Returns:
        QueryLogger instance for query-specific logging.
    """
    global _query_logger
    
    if _query_logger is None:
        setup_logging()
    
    assert _query_logger is not None  # setup_logging always sets this
    
    return _query_logger


def set_log_level(level: LogLevel | str) -> None:
    """Change the log level at runtime.
    
    Args:
        level: New log level (LogLevel enum or string like "DEBUG").
    """
    if isinstance(level, str):
        level = LogLevel[level.upper()]
    
    logger = get_logger()
    logger.setLevel(level.value)


def log_with_data(
    level: int,
    message: str,
    data: dict[str, Any] | None = None,
    logger: logging.Logger | None = None,
) -> None:
    """Log a message with additional structured data.
    
    Args:
        level: Log level (e.g., logging.INFO).
        message: Log message.
        data: Additional data to include in log output.
        logger: Logger to use. Uses root logger if not provided.
    """
    if logger is None:
        logger = get_logger()
    
    record = logger.makeRecord(
        logger.name,
        level,
        "(unknown file)",
        0,
        message,
        (),
        None,
    )
    
    if data:
        record.extra_data = data
    
    logger.handle(record)


# Convenience functions for common logging operations
def debug(message: str, **kwargs) -> None:
    """Log a debug message."""
    get_logger().debug(message, **kwargs)


def info(message: str, **kwargs) -> None:
    """Log an info message."""
    get_logger().info(message, **kwargs)


def warning(message: str, **kwargs) -> None:
    """Log a warning message."""
    get_logger().warning(message, **kwargs)


def error(message: str, **kwargs) -> None:
    """Log an error message."""
    get_logger().error(message, **kwargs)


def critical(message: str, **kwargs) -> None:
    """Log a critical message."""
    get_logger().critical(message, **kwargs)


def exception(message: str, **kwargs) -> None:
    """Log an exception with traceback."""
    get_logger().exception(message, **kwargs)


__all__ = [
    # Configuration
    "LogConfig",
    "LogFormat",
    "LogLevel",
    "LoggingError",
    # Context management
    "LogContext",
    # Loggers
    "QueryLogger",
    "setup_logging",
    "get_logger",
    "get_query_logger",
    "set_log_level",
    "log_with_data",
    # Convenience functions
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    "exception",
]