# scripts/test_day1.py

from agents.vulnerability_intake.nvd_client import NVDClient
from agents.vulnerability_intake.osv_client import OSVClient

cve = 'CVE-2022-42969'

print('=== NVD ===')
nvd = NVDClient()
r = nvd.fetch_cve(cve)

if r:
    print(f'CVE ID: {r["cve_id"]}')
    print(f'Severity: {r["severity"]} (CVSS {r["cvss_score"]})')
    print(f'Package: {r["affected_package"]}')
    print(f'Fixed in: {r["fixed_version"]}')
    print(f'CWEs: {r["cwe_ids"]}')
else:
    print("CVE not found in NVD")

print()

print('=== OSV ===')
osv = OSVClient()
r2 = osv.fetch_by_cve(cve, package='py', ecosystem='PyPI')

if r2:
    print(f'Fixed in: {r2["fixed_version"]}')
    print(f'Affected: {r2["affected_versions"]}')
    print(f'Refs: {r2["references"][0] if r2["references"] else "N/A"}')
else:
    print('Not found in OSV for this package name — try package="pytest"')