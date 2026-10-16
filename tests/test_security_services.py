"""Scope and NVD contract regressions."""
from unittest.mock import patch
import pytest
from cybersentinel.services.asset_scope import ScopePolicy
from cybersentinel.intelligence.vulnerability_catalog import CVEMatcher, CVEDatabase


def test_scope_exclusions_and_large_networks(tmp_path):
    policy = ScopePolicy(tmp_path)
    policy.save(['192.168.1.0/24', 'https://example.com'], ['192.168.1.9'])
    assert policy.permits('192.168.1.8')
    assert not policy.permits('192.168.1.9')
    assert not policy.permits('192.168.1.0/24')
    with pytest.raises(ValueError):
        policy.permits('192.168.0.0/16')
    assert policy.permits('https://example.com/path')
    assert not policy.permits('http://example.com')
    with pytest.raises(ValueError):
        policy.save(['10.0.0.0/8'], [])


def test_nvd_pages_and_uncertain_versions(tmp_path):
    matcher = CVEMatcher(db_path=tmp_path / 'nvd.db')
    cpe = 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*'
    record = {'cve': {'id': 'CVE-2025-0001', 'descriptions': [{'lang':'en','value':'Example'}],
        'configurations': [{'nodes':[{'cpeMatch':[{'vulnerable':True,'criteria':'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*','versionEndExcluding':'2.0'}]}]}]}}
    with patch.object(matcher, '_make_nvd_request', side_effect=[{'totalResults':2,'vulnerabilities':[record]}, {'totalResults':2,'vulnerabilities':[{'cve':{**record['cve'],'id':'CVE-2025-0002'}}]}]) as request:
        results = matcher.search_cves_by_cpe(cpe)
    assert len(results) == 2
    assert request.call_count == 2
    assert CVEDatabase._is_version_vulnerable('vendor-build-unknown', end_exc='2.0') is None
