# Evaluation Results

## Overall
| Metric | Value |
|---|---|
| Expected matches (ground truth) | 128 |
| Matches found | 128 |
| True positives | 128 |
| False positives | 0 |
| False negatives | 0 |
| Precision | 100.0% |
| Recall | 100.0% |
| F1 score | 100.0% |

## Per IOC type
| Type | Expected | Found | Correct | Precision | Recall |
|---|---|---|---|---|---|
| domain | 37 | 37 | 37 | 100.0% | 100.0% |
| email | 8 | 8 | 8 | 100.0% | 100.0% |
| ipv4 | 44 | 44 | 44 | 100.0% | 100.0% |
| ipv6 | 2 | 2 | 2 | 100.0% | 100.0% |
| md5 | 8 | 8 | 8 | 100.0% | 100.0% |
| sha1 | 6 | 6 | 6 | 100.0% | 100.0% |
| sha256 | 8 | 8 | 8 | 100.0% | 100.0% |
| url | 15 | 15 | 15 | 100.0% | 100.0% |

## Recall per surface variant
| Variant | Expected | Found | Recall |
|---|---|---|---|
| capitalized | 10 | 10 | 100.0% |
| exact | 84 | 84 | 100.0% |
| expanded_ipv6 | 1 | 1 | 100.0% |
| trailing_dot | 12 | 12 | 100.0% |
| upper | 3 | 3 | 100.0% |
| upper_email | 4 | 4 | 100.0% |
| upper_hash | 7 | 7 | 100.0% |
| upper_host_url | 7 | 7 | 100.0% |

## Hard negatives (must not match)
| Kind | Planted | False positives |
|---|---|---|
| domain_in_url_only | 5 | 0 |
| hash_off_by_one | 12 | 0 |
| ip_inside_url | 4 | 0 |
| near_ip | 18 | 0 |
| prefix | 6 | 0 |
| subdomain | 4 | 0 |
| suffix_tld | 5 | 0 |
| url_other_path | 8 | 0 |
| wrong_field | 12 | 0 |

## Evidence completeness
| Check | Result |
|---|---|
| Matches with all evidence fields and a verified file hash | 128 / 128 (100.0%) |
| Matches traceable to the raw file row (value and time re-verified) | 128 / 128 (100.0%) |
