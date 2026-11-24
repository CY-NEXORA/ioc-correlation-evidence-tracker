# Data Dictionary

All data is **synthetic** (documentation IP ranges and invented domains). No real malware or customer data.

## iocs.csv (indicator list)
| Column | Type | Meaning |
|---|---|---|
| value | text | The raw indicator as received (may be messy/defanged) |
| type | text | Declared type: ip, domain, url, md5, sha1, sha256, hash, email |
| source | text | Where the indicator came from (feed/team) |
| added_date | date | When the indicator was added (YYYY-MM-DD) |

## dns_log.csv
| Column | Meaning | Matched against |
|---|---|---|
| timestamp | Query time | - |
| src_ip | Client that asked | ip IOCs |
| query | Domain requested | domain IOCs |
| record_type | DNS record type | - |
| response_ip | Answer IP | ip IOCs |

## auth_log.csv
| Column | Meaning | Matched against |
|---|---|---|
| timestamp | Event time | - |
| host | Target server | - |
| username | Account used | - |
| src_ip | Source of login attempt | ip IOCs |
| event / status | Event type / result | - |

## proxy_log.csv
| Column | Meaning | Matched against |
|---|---|---|
| timestamp | Request time | - |
| client_ip | Internal client | ip IOCs |
| host | Requested host | domain IOCs |
| url | Full URL | url IOCs |
| bytes | Response size | - |

## endpoint_log.csv
| Column | Meaning | Matched against |
|---|---|---|
| timestamp | Event time | - |
| hostname | Endpoint name | - |
| file_name | File seen | - |
| file_md5 / file_sha256 | File hashes | md5 / sha256 IOCs |
| sender_email | Email sender | email IOCs |
