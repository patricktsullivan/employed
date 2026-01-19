# sanitizer.py

import re
import hashlib

class Sanitizer:
    """
    Sanitizes command lines and generates behavioral templates.
        
    Sanitization replaces variable components with placeholder tokens:
        - IP addresses -> <IP>
        - Base64 encoded data -> <DATA>
        - Temporary file paths -> <TEMP>
        - GUIDs/UUIDs/CLSIDs -> <GUID>
        - Timestamps -> <TIME>
        - Random-looking strings -> <RAND>
    
    Example:
        >>> template = Sanitizer.generate_template(alert)
        >>> print(template)
        'powershell.exe -enc <DATA> -ep bypass'
        >>> hash = Sanitizer.hash_template(template)
        >>> print(hash)
        'a1b2c3d4...'
    """

    WELL_KNOWN_SIDS = {
        # Universal
        'S-1-1-0': '<Everyone>',
        
        # Logon types
        'S-1-5-2': '<Network>',
        'S-1-5-3': '<Batch>',
        'S-1-5-4': '<Interactive>',
        'S-1-5-6': '<Service>',
        'S-1-5-7': '<Anonymous>',
        
        # Special identities
        'S-1-5-11': '<AuthenticatedUsers>',
        'S-1-5-113': '<LocalAccount>',
        'S-1-5-114': '<LocalAccountAndAdministrator>',
        
        # Local service accounts
        'S-1-5-18': '<LocalSystem>',
        'S-1-5-19': '<LocalService>',
        'S-1-5-20': '<NetworkService>',
        
        # Built-in groups (S-1-5-32-xxx)
        'S-1-5-32-544': '<Administrators>',
        'S-1-5-32-545': '<Users>',
        'S-1-5-32-546': '<Guests>',
        'S-1-5-32-547': '<PowerUsers>',
        'S-1-5-32-548': '<AccountOperators>',
        'S-1-5-32-549': '<ServerOperators>',
        'S-1-5-32-550': '<PrintOperators>',
        'S-1-5-32-551': '<BackupOperators>',
    }

    SANITIZATION_RULES = [
        # IPv4 addresses
        (
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            '<IP>',
            'IPv4 Address'
        ),

        # IPv6 addresses
        (
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            '<IP>',
            'IPv6 Address'
        ),
        
        # GUIDs/UUIDs/CLSIDs
        (
            r'\{?[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\}?',
            '<GUID>',
            'GUIDs/UUIDs/CLSIDs'
        ),

        # Windows temp paths
        (
            r'[Cc]:\\(?:Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\Temp|Temp)\\[^\s"\']+',
            '<TEMP>',
            'Windows temp file path'
        ),

        # Linux temp paths
        (
            r'/(?:tmp|var/tmp)/[^\s"\']+',
            '<TEMP>',
            'Linux temp file path'
        ),

        # Hostnames in URLs (preserve protocol)
        (
            r'(https?://)([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}',
            r'\1<HOST>',
            'URL hostname'
        ),

        # ISO timestamps
        (
            r'\b\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b',
            '<TIME>',
            'ISO timestamp'
        ),

        # Unix timestamps (10-13 digits starting with 1)
        (
            r'\b1[0-9]{9,12}\b',
            '<TIME>',
            'Unix timestamp'
        ),

        # Base64 encoded data (20+ chars to reduce false positives)
        (
            r'\b[A-Za-z0-9+/]{20,}={0,2}\b',
            '<DATA>',
            'Base64-encoded data'
        ),

        # Long hex strings (32+ chars, covers hashes and encoded data)
        (
            r'\b[0-9a-fA-F]{32,}\b',
            '<HEX>',
            'Hex string (hash or encoded data)'
        ),

        # Domain SIDs (user/computer accounts) - after well-known SID replacement
        (
            r'S-1-5-21-\d+-\d+-\d+(?:-\d+)?',
            '<SID>',
            'Domain user/computer SID'
        ),

        # Process IDs in common formats
        (
            r'\bpid[:\s]+\d+\b',
            '<PID>',
            'Process ID'
        ),

        # Random alphanumeric strings (12+ chars, mixed letters and digits)
        # Run last to avoid over-matching
        (
            r'\b(?=[A-Za-z]*\d)(?=\d*[A-Za-z])[A-Za-z0-9]{12,}\b',
            '<RAND>',
            'Random alphanumeric string'
        ),
    ]

    @classmethod
    def sanitize(cls, text: str) -> str:
        """Apply all sanitization rules to input text."""
        if not text:
            return ""

        # First pass: replace well-known SIDs with readable names
        result = cls._replace_well_known_sids(text)

        # Second pass: apply regex rules (including generic SID pattern)
        for pattern, replacement, _ in cls.SANITIZATION_RULES:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

        # Normalize whitespace
        return ' '.join(result.split())
    
    @classmethod
    def generate_template(cls, alert: dict) -> str:
        """
        Generate a behavioral template from an alert.
        
        Combines pattern_id context with sanitized command line to create
        a canonical representation of the alert's behavior.
        
        Args:
            alert: Full alert dict from CrowdStrike API
            
        Returns:
            Template string suitable for comparison or hashing
        """
        pattern_id = str(alert.get('pattern_id', 0))
        cmdline = cls.sanitize(alert.get('cmdline', ''))

        # Get parent process for additional context
        parent_details = alert.get('parent_details', {})
        parent_filename = parent_details.get('filename', '') if parent_details else ''
        
        # Get filename (the process that triggered detection)
        filename = alert.get('filename', '')

        template_parts = [
            f"pattern:{pattern_id}",
            f"cmd:{cmdline}" if cmdline else "cmd:",
            f"file:{filename}" if filename else "file:",
            f"parent:{parent_filename}" if parent_filename else "parent:"
        ]

        return '|'.join(template_parts)

    @classmethod
    def hash_template(cls, template: str) -> str:
        """
        Generate SHA-256 hash of a template.
        
        Args:
            template: Template string from generate_template()
            
        Returns:
            64-character hex string (SHA-256 hash)
        """
        return hashlib.sha256(template.encode('utf-8')).hexdigest()
    
    @classmethod
    def _replace_well_known_sids(cls, text: str) -> str:
        """Replace well-known SIDs with human-readable tokens."""
        result = text
        for sid, token in cls.WELL_KNOWN_SIDS.items():
            pattern = r'\b' + re.escape(sid) + r'\b'
            result = re.sub(pattern, token, result, flags=re.IGNORECASE)
        return result
    

def extract_qa_fields(alert: dict) -> dict:
    """
    Extract fields needed for QA analysis from a raw alert.
    
    Provides a consistent interface for accessing alert fields,
    handling missing or nested data gracefully.
    
    Args:
        alert: Full alert dict from CrowdStrike API
        
    Returns:
        Dict with normalized field names and values
    """

    # Handle nested device info
    device = alert.get('device', {}) or {}
    
    # Handle nested parent details
    parent_details = alert.get('parent_details', {}) or {}
    
    # Handle nested grandparent details
    grandparent_details = alert.get('grandparent_details', {}) or {}

    # Extract MITRE ATT&CK data from new array format
    mitre_attack = _extract_mitre_attack(alert)

    return {
        # Core identifiers (kept for JSON, hidden in HTML)
        'alert_id': alert.get('id'),
        'composite_id': alert.get('composite_id'),
        'pattern_id': alert.get('pattern_id'),
        
        # Detection metadata (human-readable)
        'display_name': alert.get('display_name'),
        'description': alert.get('description'),
        
        # Resolution and status
        'resolution': alert.get('resolution'),
        'status': alert.get('status'),
        
        # MITRE ATT&CK context (new array format)
        'mitre_attack': mitre_attack,
        
        # -------------------------------------------------------------------------
        # DEPRECATED: Flat MITRE fields (backward compatibility)
        # These fields are deprecated by CrowdStrike in favor of the mitre_attack
        # array above. Remove this section once CrowdStrike fully deprecates them.
        # -------------------------------------------------------------------------
        'tactic': _get_primary_mitre_field(mitre_attack, 'tactic', alert.get('tactic')),
        'tactic_id': _get_primary_mitre_field(mitre_attack, 'tactic_id', alert.get('tactic_id')),
        'technique': _get_primary_mitre_field(mitre_attack, 'technique', alert.get('technique')),
        'technique_id': _get_primary_mitre_field(mitre_attack, 'technique_id', alert.get('technique_id')),
        # -------------------------------------------------------------------------
        # END DEPRECATED SECTION
        # -------------------------------------------------------------------------
        
        # CrowdStrike severity and confidence
        'severity': alert.get('severity'),
        'severity_name': alert.get('severity_name'),
        'confidence': alert.get('confidence'),
        
        # Sensor action
        'pattern_disposition': alert.get('pattern_disposition'),
        'pattern_disposition_description': alert.get('pattern_disposition_description'),
        
        # Analyst info
        'assigned_to': alert.get('assigned_to_name'),
        'seconds_to_resolved': alert.get('seconds_to_resolved'),
        'seconds_to_triaged': alert.get('seconds_to_triaged'),
        
        # Host info
        'hostname': device.get('hostname'),
        'platform': alert.get('platform') or device.get('platform_name'),
        
        # Process chain
        'cmdline': alert.get('cmdline'),
        'filename': alert.get('filename'),
        'filepath': alert.get('filepath'),
        'parent_filename': parent_details.get('filename'),
        'parent_cmdline': parent_details.get('cmdline'),
        'grandparent_filename': grandparent_details.get('filename'),
        
        # User context
        'user_name': alert.get('user_name'),
        'user_id': alert.get('user_id'),
        
        # Links
        'falcon_link': alert.get('falcon_host_link'),
        
        # Timestamps
        'created_timestamp': alert.get('created_timestamp'),
        'updated_timestamp': alert.get('updated_timestamp'),
        
        # Tags (can be useful for filtering)
        'tags': alert.get('tags'),
    }


def _extract_mitre_attack(alert: dict) -> list[dict]:
    """
    Extract MITRE ATT&CK entries from alert, normalizing to array format.
    
    Handles both the new mitre_attack array format and falls back to
    constructing an entry from deprecated flat fields if needed.
    
    Args:
        alert: Full alert dict from CrowdStrike API
        
    Returns:
        List of MITRE ATT&CK entry dicts, each containing:
        - pattern_id (optional): CrowdStrike pattern ID for this entry
        - tactic_id: MITRE tactic ID (e.g., "TA0003")
        - tactic: MITRE tactic name (e.g., "Persistence")
        - technique_id: MITRE technique ID (e.g., "T1547")
        - technique: MITRE technique name (e.g., "Boot or Logon Autostart Execution")
    """
    mitre_attack = alert.get('mitre_attack')
    
    # New format: mitre_attack array exists and is not empty
    if mitre_attack and isinstance(mitre_attack, list):
        # Normalize entries to ensure consistent structure
        normalized = []
        for entry in mitre_attack:
            if isinstance(entry, dict):
                normalized.append({
                    'pattern_id': entry.get('pattern_id'),
                    'tactic_id': entry.get('tactic_id'),
                    'tactic': entry.get('tactic'),
                    'technique_id': entry.get('technique_id'),
                    'technique': entry.get('technique'),
                })
        return normalized
    
    # -------------------------------------------------------------------------
    # DEPRECATED: Fallback to flat fields
    # Remove this section once CrowdStrike fully deprecates the flat fields.
    # -------------------------------------------------------------------------
    tactic = alert.get('tactic')
    tactic_id = alert.get('tactic_id')
    technique = alert.get('technique')
    technique_id = alert.get('technique_id')
    
    # Only create an entry if we have at least some MITRE data
    if tactic or tactic_id or technique or technique_id:
        return [{
            'pattern_id': alert.get('pattern_id'),  # Use alert-level pattern_id
            'tactic_id': tactic_id,
            'tactic': tactic,
            'technique_id': technique_id,
            'technique': technique,
        }]
    # -------------------------------------------------------------------------
    # END DEPRECATED FALLBACK
    # -------------------------------------------------------------------------
    
    return []


def _get_primary_mitre_field(mitre_attack: list[dict], field: str, fallback: str | None) -> str | None:
    """
    Get the primary (first) value for a MITRE field from the array.
    
    Used for backward compatibility with code that expects flat fields.
    
    Args:
        mitre_attack: List of MITRE ATT&CK entries
        field: Field name to extract (tactic, tactic_id, technique, technique_id)
        fallback: Value to use if mitre_attack is empty
        
    Returns:
        Primary value for the field, or fallback if unavailable
    """
    if mitre_attack and len(mitre_attack) > 0:
        return mitre_attack[0].get(field)
    return fallback


# For debugging: print what each rule would match
def debug_sanitization(cmdline: str) -> None:
    """Show which sanitization rules match a given command line."""
    print(f"Original: {cmdline}\n")
    
    for pattern, replacement, description in Sanitizer.SANITIZATION_RULES:
        matches = re.findall(pattern, cmdline)
        if matches:
            print(f"  {description}:")
            for match in matches[:3]:  # Limit output
                print(f"    '{match}' -> '{replacement}'")
    
    print(f"\nSanitized: {Sanitizer.sanitize(cmdline)}")