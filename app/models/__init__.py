"""
Data models for CyberSentinel.
"""
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import time

class ScanStatus(Enum):
    """Status of a scan."""
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"

class Severity(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

@dataclass
class Vulnerability:
    """Represents a vulnerability finding."""
    id: str
    name: str
    description: str
    severity: Severity
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    solution: Optional[str] = None
    references: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Service:
    """Represents a discovered service."""
    port: int
    protocol: str
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

@dataclass
class ScanResult:
    """Represents the result of a scan."""
    scan_id: str
    target: str
    scan_type: str
    status: ScanStatus
    start_time: float
    end_time: Optional[float] = None
    error: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the scan result to a dictionary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "scan_type": self.scan_type,
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.end_time - self.start_time if self.end_time else None,
            "error": self.error,
            "options": self.options,
            "results": self.results
        }
