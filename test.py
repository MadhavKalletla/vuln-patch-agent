import requests, json
cve_id = 'CVE-2022-42969'
url =f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
data = requests.get(url, headers={'User-Agent': 'learn/1.0'}).json()
cve = data['vulnerabilities'][0]['cve']
print('ID: ', cve['id'])
print('Published: ', cve['published'])
print('Severity: ',
cve['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'])
print('CVSS Score: ',
cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'])
print('Description: ', cve['descriptions'][0]['value'][:140])
print('CWE IDs: ', [w['description'][0]['value']
 for w in cve.get('weaknesses', [])])
