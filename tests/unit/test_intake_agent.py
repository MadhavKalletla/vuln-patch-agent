import pytest
from unittest.mock import MagicMock

from agents.vulnerability_intake.intake_agent import VulnerabilityIntakeAgent
from agents.vulnerability_intake.models import Severity


MOCK_NVD = {
    'cve_id': 'CVE-2022-42969',
    'severity': 'HIGH',
    'cvss_score': 7.5,
    'affected_package': 'py',
    'affected_versions': ['<1.11.0'],
    'fixed_version': '1.11.0',
    'cwe_ids': ['CWE-400'],
    'description': 'ReDoS in py.',
    'published': '2022-10-16T00:00:00',
}

MOCK_OSV = {
    'osv_id': 'PYSEC-2022-301',
    'aliases': ['CVE-2022-42969'],
    'summary': 'ReDoS in py.',
    'affected_versions': ['>=1.0.0'],
    'fixed_version': '1.11.0',
    'references': ['https://github.com/pytest-dev/py/issues/287'],
}


def agent_with_mocks(nvd=MOCK_NVD, osv=MOCK_OSV):
    a = VulnerabilityIntakeAgent()
    a.nvd = MagicMock()
    a.osv = MagicMock()

    a.nvd.fetch_cve.return_value = nvd
    a.osv.fetch_by_cve.return_value = osv

    return a


def test_returns_correct_severity_and_score():
    ctx = agent_with_mocks().run('CVE-2022-42969', package='py')

    assert ctx.cve_id == 'CVE-2022-42969'
    assert ctx.severity == Severity.HIGH
    assert ctx.cvss_score == 7.5


def test_fixed_version_from_osv_takes_priority():
    ctx = agent_with_mocks().run('CVE-2022-42969', package='py')

    assert ctx.fixed_version == '1.11.0'


def test_confidence_high_when_both_sources_agree():
    ctx = agent_with_mocks().run('CVE-2022-42969', package='py')

    assert ctx.confidence >= 0.9


def test_remediation_hint_populated_for_cwe400():
    ctx = agent_with_mocks().run('CVE-2022-42969', package='py')

    assert ctx.remediation_hint is not None
    assert 'upgrade' in ctx.remediation_hint.lower()


def test_works_with_osv_unavailable():
    # OSV returns None (package name not recognised)
    ctx = agent_with_mocks(osv=None).run('CVE-2022-42969', package='py')

    assert ctx.fixed_version == '1.11.0'  # falls back to NVD
    assert ctx.confidence < 0.9  # lower confidence without OSVc