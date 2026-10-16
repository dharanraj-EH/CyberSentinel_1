"""Common evidence, report safety and remediation persistence."""
import json
import pytest
from cybersentinel.services.assessment_store import AssessmentWorkspace


def test_reports_escape_evidence_and_redact_credentials(tmp_path):
    workspace = AssessmentWorkspace('one', tmp_path)
    assessment = workspace.record('web', '<script>alert(1)</script>', {'headers': {
        'vulnerable': True, 'severity': 'low', 'evidence': '<script>payload</script>',
        'recommendation': 'Set CSP', 'cookie': 'sensitive-value'}})
    bundle = workspace.export_bundle(assessment)
    html = (bundle / 'report.html').read_text(encoding='utf-8')
    assert '<script>' not in html
    assert '&lt;script&gt;' in html
    assert 'sensitive-value' not in (bundle / 'report.json').read_text()
    assert (bundle / 'report.pdf').read_bytes().startswith(b'%PDF')


def test_history_is_account_separated(tmp_path):
    first = AssessmentWorkspace('one', tmp_path)
    second = AssessmentWorkspace('two', tmp_path)
    first.record('network', 'localhost', {'ports': []})
    assert len(first.history()) == 1
    assert second.history() == []


def test_compare_partial_does_not_claim_resolution(tmp_path):
    workspace = AssessmentWorkspace('one', tmp_path)
    old = workspace.record('network', 'localhost', {'ports': [{'port': 22, 'state': 'open'}]})
    new = workspace.record('network', 'localhost', {'ports': [], 'error': 'timeout'})
    comparison = workspace.compare(new, old)
    assert comparison['unverified_missing']
    assert 'not_observed' not in comparison


def test_false_positive_requires_reason(tmp_path):
    workspace = AssessmentWorkspace('one', tmp_path)
    item = workspace.record('network', 'localhost', {'ports': [{'port': 22, 'state': 'open'}]})
    key = item['findings'][0]['fingerprint']
    with pytest.raises(ValueError):
        workspace.update(key, 'Analyst', 'False positive', '')
    workspace.update(key, 'Analyst', 'False positive', 'Expected service')
    assert workspace.workflow(key)['note'] == 'Expected service'


def test_backup_restores_history(tmp_path):
    original = AssessmentWorkspace('one', tmp_path)
    original.record('network', 'localhost', {'ports': []})
    archive = tmp_path / 'backup.zip'
    original.backup(archive)
    restored = AssessmentWorkspace('two', tmp_path)
    restored.restore(archive)
    assert len(restored.history()) == 1


def test_restore_rejects_path_traversal(tmp_path):
    import zipfile
    archive = tmp_path / 'unsafe.zip'
    with zipfile.ZipFile(archive, 'w') as output:
        output.writestr('assessments.db', '')
        output.writestr('../outside', 'bad')
    workspace = AssessmentWorkspace('one', tmp_path)
    with pytest.raises(ValueError, match='Unsafe'):
        workspace.restore(archive)


def test_consolidated_report_keeps_module_coverage(tmp_path):
    workspace = AssessmentWorkspace('one', tmp_path)
    workspace.record('network', 'localhost', {'ports': []})
    workspace.record('web', 'http://localhost', {'headers': {'vulnerable': False}})
    combined = workspace.consolidated('localhost')
    assert set(combined['raw']) == {'network', 'web'}
    assert 'Missing modules were not assessed' in combined['coverage']
