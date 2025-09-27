"""
CVE (Common Vulnerabilities and Exposures) matcher for CyberSentinel.

This module provides functionality to match software versions against known
vulnerabilities from the NVD (National Vulnerability Database).
"""

import json
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import requests
from packaging import version
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Set up logging
logger = logging.getLogger(__name__)

# Constants
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
CACHE_DIR = os.path.expanduser("~/.cybersentinel/cve_cache")
CACHE_EXPIRY_DAYS = 7


class CVEDatabase:
    """
    A simple SQLite database for storing and querying CVE data.
    """

    def __init__(self, db_path: str = None):
        """
        Initialize the CVE database.

        Args:
            db_path: Path to the SQLite database file. If None, uses default location.
        """
        if db_path is None:
            os.makedirs(CACHE_DIR, exist_ok=True)
            db_path = os.path.join(CACHE_DIR, "cve_database.db")

        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_items (
                cve_id TEXT PRIMARY KEY,
                published_date TEXT,
                last_modified_date TEXT,
                description TEXT,
                cvss_score REAL,
                cvss_severity TEXT,
                cpe_match_string TEXT,
                vulnerable_software TEXT,
                raw_json TEXT
            )
            """)
            
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS cpe_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                cpe_uri TEXT,
                version_start_including TEXT,
                version_start_excluding TEXT,
                version_end_including TEXT,
                version_end_excluding TEXT,
                vulnerable BOOLEAN,
                FOREIGN KEY (cve_id) REFERENCES cve_items (cve_id)
            )
            """)
            
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """)
            
            # Create indexes for better query performance
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_items_cvss_severity 
            ON cve_items (cvss_severity)
            """)
            
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cpe_matches_cpe_uri 
            ON cpe_matches (cpe_uri)
            """)
            
            conn.commit()

    def add_cve_item(self, cve_data: dict) -> None:
        """
        Add a CVE item to the database.

        Args:
            cve_data: Dictionary containing CVE data from NVD API
        """
        try:
            cve_id = cve_data.get('cve', {}).get('CVE_data_meta', {}).get('ID')
            if not cve_id:
                logger.warning("CVE data missing CVE ID, skipping")
                return

            # Extract basic CVE information
            description = ''
            for desc in cve_data.get('cve', {}).get('description', {}).get('description_data', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break

            # Get CVSS v3 score if available, otherwise fall back to v2
            impact = cve_data.get('impact', {})
            cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
            cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {})
            
            cvss_score = cvss_v3.get('baseScore')
            cvss_severity = cvss_v3.get('baseSeverity')
            
            if cvss_score is None and cvss_v2:
                cvss_score = cvss_v2.get('baseScore')
                cvss_severity = cvss_v2.get('severity', '').upper()

            # Extract CPE matches
            cpe_matches = []
            nodes = cve_data.get('configurations', {}).get('nodes', [])
            for node in nodes:
                for cpe_match in node.get('cpe_match', []):
                    if cpe_match.get('vulnerable', False):
                        cpe_matches.append({
                            'cpe_uri': cpe_match.get('cpe23Uri', ''),
                            'version_start_including': cpe_match.get('versionStartIncluding'),
                            'version_start_excluding': cpe_match.get('versionStartExcluding'),
                            'version_end_including': cpe_match.get('versionEndIncluding'),
                            'version_end_excluding': cpe_match.get('versionEndExcluding'),
                            'vulnerable': cpe_match.get('vulnerable', True)
                        })

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Insert or replace CVE item
                cursor.execute("""
                INSERT OR REPLACE INTO cve_items (
                    cve_id, published_date, last_modified_date, description,
                    cvss_score, cvss_severity, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve_id,
                    cve_data.get('publishedDate'),
                    cve_data.get('lastModifiedDate'),
                    description,
                    cvss_score,
                    cvss_severity,
                    json.dumps(cve_data)
                ))
                
                # Delete existing CPE matches for this CVE
                cursor.execute("DELETE FROM cpe_matches WHERE cve_id = ?", (cve_id,))
                
                # Insert new CPE matches
                for match in cpe_matches:
                    cursor.execute("""
                    INSERT INTO cpe_matches (
                        cve_id, cpe_uri, version_start_including, version_start_excluding,
                        version_end_including, version_end_excluding, vulnerable
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cve_id,
                        match['cpe_uri'],
                        match['version_start_including'],
                        match['version_start_excluding'],
                        match['version_end_including'],
                        match['version_end_excluding'],
                        match['vulnerable']
                    ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error adding CVE item to database: {e}", exc_info=True)

    def get_cve_by_id(self, cve_id: str) -> Optional[dict]:
        """
        Retrieve a CVE by its ID.

        Args:
            cve_id: CVE ID (e.g., 'CVE-2021-44228')

        Returns:
            Dictionary containing CVE data, or None if not found
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get CVE item
                cursor.execute("""
                SELECT * FROM cve_items WHERE cve_id = ?
                """, (cve_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Convert row to dict
                cve_data = dict(row)
                
                # Get CPE matches
                cursor.execute("""
                SELECT * FROM cpe_matches WHERE cve_id = ?
                """, (cve_id,))
                
                cpe_matches = [dict(match) for match in cursor.fetchall()]
                cve_data['cpe_matches'] = cpe_matches
                
                return cve_data
                
        except Exception as e:
            logger.error(f"Error retrieving CVE {cve_id}: {e}", exc_info=True)
            return None

    def get_cves_by_cpe(self, cpe_uri: str, version: str = None) -> List[dict]:
        """
        Retrieve CVEs that match a given CPE URI and optionally a version.

        Args:
            cpe_uri: CPE URI (e.g., 'cpe:2.3:a:apache:log4j:2.14.1')
            version: Version to check against version ranges in CPE matches

        Returns:
            List of matching CVE dictionaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # First, get all CVEs that have a CPE match for the given URI
                cursor.execute("""
                SELECT DISTINCT cve_id FROM cpe_matches 
                WHERE cpe_uri LIKE ?
                """, (f"{cpe_uri}%",))
                
                cve_ids = [row[0] for row in cursor.fetchall()]
                
                if not cve_ids:
                    return []
                
                # Get full CVE data for each matching CVE
                placeholders = ','.join(['?'] * len(cve_ids))
                cursor.execute(f"""
                SELECT * FROM cve_items 
                WHERE cve_id IN ({placeholders})
                """, cve_ids)
                
                cves = []
                for row in cursor.fetchall():
                    cve = dict(row)
                    
                    # Get CPE matches for this CVE
                    cursor.execute("""
                    SELECT * FROM cpe_matches 
                    WHERE cve_id = ? AND cpe_uri LIKE ?
                    """, (cve['cve_id'], f"{cpe_uri}%"))
                    
                    cpe_matches = [dict(match) for match in cursor.fetchall()]
                    
                    # If version is provided, filter CPE matches by version
                    if version and cpe_matches:
                        filtered_matches = []
                        for match in cpe_matches:
                            if self._is_version_vulnerable(
                                version,
                                match.get('version_start_including'),
                                match.get('version_start_excluding'),
                                match.get('version_end_including'),
                                match.get('version_end_excluding')
                            ):
                                filtered_matches.append(match)
                        
                        # Only include CVE if there are matching CPEs for this version
                        if filtered_matches:
                            cve['cpe_matches'] = filtered_matches
                            cves.append(cve)
                    else:
                        # Include all CPE matches if no version is provided
                        cve['cpe_matches'] = cpe_matches
                        cves.append(cve)
                
                return cves
                
        except Exception as e:
            logger.error(f"Error querying CVEs by CPE {cpe_uri}: {e}", exc_info=True)
            return []

    def _is_version_vulnerable(
        self,
        version_str: str,
        start_inc: str = None,
        start_exc: str = None,
        end_inc: str = None,
        end_exc: str = None
    ) -> bool:
        """
        Check if a version is within a vulnerable range.

        Args:
            version_str: Version to check
            start_inc: Start of range (inclusive)
            start_exc: Start of range (exclusive)
            end_inc: End of range (inclusive)
            end_exc: End of range (exclusive)

        Returns:
            True if the version is within the vulnerable range, False otherwise
        """
        try:
            v = version.parse(version_str)
            
            # Check start of range (inclusive)
            if start_inc and version.parse(start_inc) > v:
                return False
                
            # Check start of range (exclusive)
            if start_exc and version.parse(start_exc) >= v:
                return False
                
            # Check end of range (inclusive)
            if end_inc and version.parse(end_inc) < v:
                return False
                
            # Check end of range (exclusive)
            if end_exc and version.parse(end_exc) <= v:
                return False
                
            return True
            
        except version.InvalidVersion:
            # If version parsing fails, do a simple string comparison
            logger.warning(f"Could not parse version: {version_str}")
            return True  # Assume vulnerable if we can't parse the version

    def get_cve_count(self) -> int:
        """
        Get the total number of CVEs in the database.

        Returns:
            Number of CVEs in the database
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM cve_items")
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error getting CVE count: {e}", exc_info=True)
            return 0

    def clear_database(self) -> bool:
        """
        Clear all data from the database.

        Returns:
            True if successful, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM cve_items")
                cursor.execute("DELETE FROM cpe_matches")
                cursor.execute("DELETE FROM metadata")
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error clearing database: {e}", exc_info=True)
            return False


class CVEMatcher:
    """
    A class for matching software versions against known vulnerabilities.
    """
    
    def __init__(self, api_key: str = None, cache_dir: str = None, db_path: str = None):
        """
        Initialize the CVE matcher.

        Args:
            api_key: NVD API key (optional but recommended)
            cache_dir: Directory to store cached CVE data
            db_path: Path to the SQLite database file
        """
        self.api_key = api_key
        self.cache_dir = cache_dir or CACHE_DIR
        self.db = CVEDatabase(db_path)
        
        # Set up requests session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def _make_nvd_request(self, url: str, params: dict = None) -> Optional[dict]:
        """
        Make a request to the NVD API with rate limiting and error handling.

        Args:
            url: API endpoint URL
            params: Query parameters

        Returns:
            JSON response as a dictionary, or None if the request failed
        """
        headers = {
            "User-Agent": "CyberSentinel/1.0",
            "Accept": "application/json"
        }
        
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            # Respect rate limiting (10 requests per minute without API key, 50 with API key)
            remaining = int(response.headers.get('X-RateLimit-Remaining', 10))
            if remaining <= 1:
                reset_time = int(response.headers.get('X-RateLimit-Reset', 60))
                logger.info(f"Rate limit reached. Waiting {reset_time} seconds...")
                time.sleep(reset_time + 1)
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Status code: {e.response.status_code}")
                logger.error(f"Response: {e.response.text}")
            return None
    
    def _get_cve_cache_path(self, cve_id: str) -> str:
        """
        Get the cache file path for a CVE.

        Args:
            cve_id: CVE ID (e.g., 'CVE-2021-44228')

        Returns:
            Path to the cache file
        """
        return os.path.join(self.cache_dir, f"{cve_id}.json")
    
    def _is_cache_valid(self, file_path: str, max_age_days: int = CACHE_EXPIRY_DAYS) -> bool:
        """
        Check if a cache file is still valid.

        Args:
            file_path: Path to the cache file
            max_age_days: Maximum age of the cache file in days

        Returns:
            True if the cache is valid, False otherwise
        """
        if not os.path.exists(file_path):
            return False
            
        file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
        cache_age = datetime.now() - file_mtime
        
        return cache_age.days < max_age_days
    
    def _load_cve_from_cache(self, cve_id: str) -> Optional[dict]:
        """
        Load CVE data from the local cache.

        Args:
            cve_id: CVE ID (e.g., 'CVE-2021-44228')

        Returns:
            CVE data as a dictionary, or None if not found in cache
        """
        cache_path = self._get_cve_cache_path(cve_id)
        
        if not os.path.exists(cache_path) or not self._is_cache_valid(cache_path):
            return None
            
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading CVE {cve_id} from cache: {e}")
            return None
    
    def _save_cve_to_cache(self, cve_id: str, cve_data: dict) -> bool:
        """
        Save CVE data to the local cache.

        Args:
            cve_id: CVE ID (e.g., 'CVE-2021-44228')
            cve_data: CVE data to cache

        Returns:
            True if successful, False otherwise
        """
        cache_path = self._get_cve_cache_path(cve_id)
        
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cve_data, f, ensure_ascii=False, indent=2)
            return True
        except IOError as e:
            logger.error(f"Error saving CVE {cve_id} to cache: {e}")
            return False
    
    def fetch_cve(self, cve_id: str, use_cache: bool = True) -> Optional[dict]:
        """
        Fetch CVE data from the NVD API or local cache.

        Args:
            cve_id: CVE ID (e.g., 'CVE-2021-44228')
            use_cache: Whether to use cached data if available

        Returns:
            CVE data as a dictionary, or None if not found
        """
        # Check if CVE is already in the database
        cve_data = self.db.get_cve_by_id(cve_id)
        if cve_data and use_cache:
            logger.debug(f"Found CVE {cve_id} in database")
            return cve_data
        
        # Try to load from cache if enabled
        if use_cache:
            cve_data = self._load_cve_from_cache(cve_id)
            if cve_data:
                logger.debug(f"Loaded CVE {cve_id} from cache")
                # Update database with cached data
                self.db.add_cve_item(cve_data)
                return cve_data
        
        # Fetch from NVD API
        url = f"{NVD_API_BASE_URL}/{cve_id}"
        response = self._make_nvd_request(url)
        
        if not response or 'result' not in response:
            logger.error(f"Failed to fetch CVE {cve_id} from NVD")
            return None
        
        cve_data = response.get('result', {}).get('CVE_Items', [{}])[0]
        if not cve_data:
            logger.error(f"No data found for CVE {cve_id}")
            return None
        
        # Save to cache and database
        self._save_cve_to_cache(cve_id, cve_data)
        self.db.add_cve_item(cve_data)
        
        return cve_data
    
    def search_cves_by_cpe(self, cpe_uri: str, version: str = None) -> List[dict]:
        """
        Search for CVEs that affect a given CPE and optionally a specific version.

        Args:
            cpe_uri: CPE URI (e.g., 'cpe:2.3:a:apache:log4j:2.14.1')
            version: Version to check against version ranges in CPE matches

        Returns:
            List of matching CVE dictionaries
        """
        # First check the database
        results = self.db.get_cves_by_cpe(cpe_uri, version)
        
        if results:
            logger.debug(f"Found {len(results)} CVEs in database for CPE {cpe_uri}")
            return results
        
        # If not in database, try to fetch from NVD API
        logger.info(f"No CVEs found in database for CPE {cpe_uri}, querying NVD API...")
        
        # Convert CPE 2.3 to CPE 2.2 format for NVD API
        cpe22_uri = self._convert_cpe23_to_cpe22(cpe_uri)
        if not cpe22_uri:
            logger.error(f"Invalid CPE 2.3 URI: {cpe_uri}")
            return []
        
        # Search NVD API for CVEs matching this CPE
        url = f"{NVD_API_BASE_URL}"
        params = {
            'cpeMatchString': cpe22_uri,
            'resultsPerPage': 2000  # Maximum allowed by NVD API
        }
        
        response = self._make_nvd_request(url, params=params)
        if not response or 'result' not in response:
            logger.error("Failed to search CVEs by CPE")
            return []
        
        # Process and store the results
        cve_items = response.get('result', {}).get('CVE_Items', [])
        
        for cve_item in cve_items:
            self.db.add_cve_item(cve_item)
            self._save_cve_to_cache(
                cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID'),
                cve_item
            )
        
        # Now get the results from the database to ensure consistent format
        return self.db.get_cves_by_cpe(cpe_uri, version)
    
    def _convert_cpe23_to_cpe22(self, cpe23_uri: str) -> Optional[str]:
        """
        Convert a CPE 2.3 URI to CPE 2.2 format.

        Args:
            cpe23_uri: CPE 2.3 URI (e.g., 'cpe:2.3:a:apache:log4j:2.14.1')

        Returns:
            CPE 2.2 URI, or None if conversion fails
        """
        if not cpe23_uri.startswith('cpe:2.3:'):
            return None
            
        # Extract the CPE components
        parts = cpe23_uri.split(':')
        if len(parts) < 6:  # At least 6 parts required (cpe:2.3:type:vendor:product:version:...)
            return None
            
        # Reconstruct in CPE 2.2 format
        cpe22_parts = ['cpe:/']
        
        # Type (a for application, o for OS, h for hardware)
        cpe_type = parts[2]
        if cpe_type == 'a':
            cpe22_parts.append('a')
        elif cpe_type == 'o':
            cpe22_parts.append('o')
        elif cpe_type == 'h':
            cpe22_parts.append('h')
        else:
            cpe22_parts.append('a')  # Default to application
        
        # Vendor, product, version, update, edition
        for i in range(3, min(8, len(parts))):
            part = parts[i]
            if part == '*':
                part = ''
            cpe22_parts.append(':' + part)
        
        # Join and clean up
        cpe22_uri = ''.join(cpe22_parts)
        cpe22_uri = cpe22_uri.rstrip(':')
        
        return cpe22_uri
    
    def check_vulnerability(self, cpe_uri: str, version: str) -> dict:
        """
        Check if a given software version is vulnerable to any known CVEs.

        Args:
            cpe_uri: CPE URI (e.g., 'cpe:2.3:a:apache:log4j:2.14.1')
            version: Software version to check

        Returns:
            Dictionary with vulnerability information
        """
        result = {
            'cpe_uri': cpe_uri,
            'version': version,
            'is_vulnerable': False,
            'vulnerabilities': [],
            'severity_counts': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'UNKNOWN': 0
            },
            'highest_severity': 'NONE',
            'total_vulnerabilities': 0
        }
        
        # Search for CVEs affecting this CPE and version
        cves = self.search_cves_by_cpe(cpe_uri, version)
        
        if not cves:
            return result
        
        # Process the CVEs
        for cve in cves:
            severity = cve.get('cvss_severity', 'UNKNOWN').upper()
            if severity not in result['severity_counts']:
                severity = 'UNKNOWN'
                
            result['vulnerabilities'].append({
                'cve_id': cve.get('cve_id'),
                'description': cve.get('description', 'No description available'),
                'severity': severity,
                'cvss_score': cve.get('cvss_score'),
                'published_date': cve.get('published_date')
            })
            
            result['severity_counts'][severity] += 1
            result['total_vulnerabilities'] += 1
        
        # Determine highest severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            if result['severity_counts'][severity] > 0:
                result['highest_severity'] = severity
                result['is_vulnerable'] = True
                break
        
        return result
    
    def get_cve_summary(self) -> dict:
        """
        Get a summary of CVEs in the database.

        Returns:
            Dictionary with CVE summary statistics
        """
        summary = {
            'total_cves': 0,
            'by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'UNKNOWN': 0
            },
            'by_year': {},
            'last_updated': None
        }
        
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get total count
                cursor.execute("SELECT COUNT(*) FROM cve_items")
                summary['total_cves'] = cursor.fetchone()[0]
                
                # Get count by severity
                cursor.execute("""
                SELECT cvss_severity, COUNT(*) as count 
                FROM cve_items 
                GROUP BY cvss_severity
                """)
                
                for row in cursor.fetchall():
                    severity = row['cvss_severity'] or 'UNKNOWN'
                    severity = severity.upper()
                    if severity not in summary['by_severity']:
                        severity = 'UNKNOWN'
                    summary['by_severity'][severity] = row['count']
                
                # Get count by year
                cursor.execute("""
                SELECT SUBSTR(cve_id, 5, 4) as year, COUNT(*) as count
                FROM cve_items
                WHERE cve_id LIKE 'CVE-____-%%'
                GROUP BY year
                ORDER BY year DESC
                """)
                
                for row in cursor.fetchall():
                    summary['by_year'][row['year']] = row['count']
                
                # Get last update time
                cursor.execute("""
                SELECT MAX(last_modified_date) as last_updated
                FROM cve_items
                """)
                
                row = cursor.fetchone()
                if row and row['last_updated']:
                    summary['last_updated'] = row['last_updated']
                
                return summary
                
        except Exception as e:
            logger.error(f"Error generating CVE summary: {e}", exc_info=True)
            return summary
    
    def update_database(self, full_update: bool = False) -> dict:
        """
        Update the local CVE database from the NVD.

        Args:
            full_update: If True, perform a full update (slower). 
                        If False, only fetch updates since the last check.

        Returns:
            Dictionary with update statistics
        """
        result = {
            'success': False,
            'message': '',
            'added': 0,
            'updated': 0,
            'errors': 0,
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'duration_seconds': 0
        }
        
        try:
            # Get the last update time if not doing a full update
            last_update = None
            if not full_update:
                with sqlite3.connect(self.db.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                    SELECT MAX(last_modified_date) as last_updated
                    FROM cve_items
                    """)
                    row = cursor.fetchone()
                    if row and row[0]:
                        last_update = row[0]
            
            # Build the API URL
            url = f"{NVD_API_BASE_URL}"
            params = {
                'resultsPerPage': 2000,  # Maximum allowed by NVD API
                'startIndex': 0
            }
            
            if last_update and not full_update:
                # Add 1 second to avoid getting the same CVE multiple times
                last_update_dt = datetime.strptime(last_update, '%Y-%m-%dT%H:%MZ')
                last_update_dt += timedelta(seconds=1)
                params['modStartDate'] = last_update_dt.strftime('%Y-%m-%dT%H:%M:00.000') + ' UTC-00:00'
                logger.info(f"Fetching CVEs modified since {params['modStartDate']}")
            else:
                logger.info("Performing full CVE database update")
            
            # Fetch all pages of results
            total_results = 0
            processed = 0
            
            while True:
                response = self._make_nvd_request(url, params=params)
                if not response or 'result' not in response:
                    result['message'] = "Failed to fetch CVE data from NVD"
                    return result
                
                # Update total results on first page
                if params['startIndex'] == 0:
                    total_results = response.get('totalResults', 0)
                    logger.info(f"Found {total_results} CVEs to process")
                    
                    if total_results == 0:
                        result['success'] = True
                        result['message'] = "No new CVEs to update"
                        return result
                
                # Process CVEs in this page
                cve_items = response.get('result', {}).get('CVE_Items', [])
                for cve_item in cve_items:
                    try:
                        self.db.add_cve_item(cve_item)
                        cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                        if cve_id:
                            self._save_cve_to_cache(cve_id, cve_item)
                            
                            # Determine if this is an add or update
                            if last_update and cve_item.get('lastModifiedDate', '') > last_update:
                                result['updated'] += 1
                            else:
                                result['added'] += 1
                    except Exception as e:
                        logger.error(f"Error processing CVE: {e}", exc_info=True)
                        result['errors'] += 1
                
                # Update progress
                processed += len(cve_items)
                logger.info(f"Processed {processed} of {total_results} CVEs ({processed/max(1, total_results)*100:.1f}%)")
                
                # Check if there are more results
                if 'nextPage' in response.get('result', {}).get('links', {}) and len(cve_items) > 0:
                    params['startIndex'] += params['resultsPerPage']
                    
                    # Add a small delay to avoid hitting rate limits
                    time.sleep(1)
                else:
                    break
            
            # Update result
            result['success'] = True
            result['message'] = f"Successfully updated {result['added']} new and {result['updated']} modified CVEs"
            
        except Exception as e:
            result['message'] = f"Error during database update: {str(e)}"
            logger.error(result['message'], exc_info=True)
        finally:
            # Update end time and duration
            end_time = datetime.now()
            result['end_time'] = end_time.isoformat()
            result['duration_seconds'] = (
                datetime.fromisoformat(result['end_time']) - 
                datetime.fromisoformat(result['start_time'])
            ).total_seconds()
            
            # Log completion
            logger.info(f"CVE database update completed in {result['duration_seconds']:.1f} seconds: {result['message']}")
            
        return result


def main():
    """Example usage of the CVEMatcher class."""
    import argparse
    import pprint
    
    parser = argparse.ArgumentParser(description='Check for CVEs affecting a specific software version.')
    parser.add_argument('cpe', help='CPE URI (e.g., cpe:2.3:a:apache:log4j:2.14.1)')
    parser.add_argument('--version', help='Software version (if not included in CPE URI)')
    parser.add_argument('--api-key', help='NVD API key (recommended for frequent use)')
    parser.add_argument('--update', action='store_true', help='Update the CVE database before checking')
    parser.add_argument('--full-update', action='store_true', help='Perform a full database update (slower)')
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(os.path.join(CACHE_DIR, 'cve_scanner.log'))
        ]
    )
    
    # Initialize the CVE matcher
    matcher = CVEMatcher(api_key=args.api_key)
    
    # Update the database if requested
    if args.update or args.full_update:
        print("Updating CVE database...")
        result = matcher.update_database(full_update=args.full_update)
        print(result['message'])
        
        if not result['success']:
            print("Database update failed. Continuing with existing data...")
    
    # Extract version from CPE if not provided
    cpe_parts = args.cpe.split(':')
    if not args.version and len(cpe_parts) >= 5:
        args.version = cpe_parts[4]
    
    # Check for vulnerabilities
    print(f"\nChecking for vulnerabilities in {args.cpe} (version: {args.version or 'any'})...")
    result = matcher.check_vulnerability(args.cpe, args.version)
    
    # Print results
    if result['is_vulnerable']:
        print(f"\n[31mVULNERABLE - {result['total_vulnerabilities']} issues found ({result['highest_severity']} severity)[0m")
    else:
        print("\n[32mNo known vulnerabilities found.[0m")
    
    # Print summary
    print("\nVulnerability Summary:")
    for severity, count in result['severity_counts'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    # Print details of critical and high severity issues
    if result['vulnerabilities']:
        print("\nTop Vulnerabilities:")
        for vuln in sorted(
            result['vulnerabilities'], 
            key=lambda x: (x['severity'], x['cvss_score'] or 0), 
            reverse=True
        )[:5]:  # Show top 5
            print(f"\n  [33m{vuln['cve_id']}[0m ({vuln['severity']}, CVSS: {vuln['cvss_score'] or 'N/A'})")
            print(f"  Published: {vuln.get('published_date', 'N/A')}")
            print(f"  {vuln['description'][:200]}...")
    
    # Print database info
    summary = matcher.get_cve_summary()
    print(f"\nDatabase contains {summary['total_cves']} CVEs (last updated: {summary['last_updated'] or 'never'})")


if __name__ == "__main__":
    main()
