# Evaluation report (M9)

Generated 2026-10-13T14:56:36+00:00 from run `demo` (91,106 records, 7 days, 40 users, plus multi-year history). Mode: compose. Pricing `2026-10-aws-us-east-1-v1`, modelled scale x100,000.

Produced by `python -m benchmarks.report`; every number below is measured on this deployment.

## Targets (plan.md section 11)

| Metric | Target | Result | |
|---|---|---|---|
| Tier-hit rate (rules answered fully at tier 1/2) | ≥ 70 % | 73.7 % | ✅ |
| Detection recall at tier 1/2 vs full rehydration (min over rules) | ≥ 0.95 | 1.0000 | ✅ |
| Restore ratio, IOC sweeps (max) | ≤ 5 % | 1.7 % | ✅ |
| LLM ATT&CK mapping accuracy | ≥ 0.8 | 1.0000 | ✅ |
| Cost estimate error after calibration (median) | ≤ 25 % | 0.0 % | ✅ |
| Storage ratio (summary + artefacts + index) / raw | report | 0.6593 | |
| Break-even (hunts per year, 7-day / 5-year hunts) | report | 105.5700 / 0.4000 | |

## Tier distribution and latency

| Tier | Rules | p50 latency | p95 latency |
|---|---|---|---|
| 1 | 2 | 208 ms | 211 ms |
| 2 | 12 | 207 ms | 306 ms |
| 3 | 5 | 784 ms | 7291 ms |

## Per-rule fidelity

| Rule | Tier | Exact | Coverage | Raw hits | Recall (entity) | Recall (event) | Label precision (tier / raw) | Restored | Est. / actual cost |
|---|---|---|---|---|---|---|---|---|---|
| aws_cloudtrail_tampering | 2 | yes | 100.0 % | 0 | – | – | – / – | 0 B | 0.0026 / 0.0026 |
| dns_ioc_domains | 3 | yes | 0.0 % | 4 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 50,517 B | 0.1166 / 0.1308 |
| dns_tunnelling | 2 | upper bound | 100.0 % | 1 | 1.0000 | – | 1.0000 / 1.0000 | 0 B | 0.0043 / 0.0043 |
| ecs_documentation_range_traffic | 3 | yes | 0.0 % | 349 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 25,909,068 B | 59.7612 / 59.7612 |
| net_miner_pool_port | 2 | yes | 100.0 % | 30 | 1.0000 | – | 1.0000 / 1.0000 | 0 B | 0.0174 / 0.0174 |
| net_smb_fanout | 2 | upper bound | 100.0 % | 1 | 1.0000 | – | 1.0000 / 1.0000 | 0 B | 0.0174 / 0.0174 |
| proxy_c2_ioc | 3 | yes | 0.0 % | 4 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 70,723 B | 0.1632 / 0.1830 |
| proxy_large_upload | 2 | yes | 100.0 % | 18 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 0 B | 0.0030 / 0.0030 |
| proxy_suspicious_user_agent | 3 | yes | 0.0 % | 4 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 4,143,751 B | 9.5579 / 9.5579 |
| win_admin_group_add | 2 | yes | 100.0 % | 1 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 0 B | 0.0206 / 0.0206 |
| win_brute_force | 2 | upper bound | 100.0 % | 1 | 1.0000 | – | 1.0000 / 1.0000 | 0 B | 0.0037 / 0.0037 |
| win_certutil_download | 2 | yes | 100.0 % | 1 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 0 B | 0.0090 / 0.0090 |
| win_encoded_powershell | 2 | yes | 100.0 % | 1 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 0 B | 0.0090 / 0.0090 |
| win_lolbin_proxy_execution | 2 | yes | 100.0 % | 3 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 0 B | 0.0090 / 0.0090 |
| win_miner_commandline | 2 | yes | 100.0 % | 1 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 0 B | 0.0090 / 0.0090 |
| win_office_spawns_shell | 1 | yes | 100.0 % | 1 | 1.0000 | – | 1.0000 / 1.0000 | 0 B | 0.0024 / 0.0024 |
| win_password_spray | 2 | upper bound | 100.0 % | 1 | 1.0000 | – | 1.0000 / 1.0000 | 0 B | 0.0037 / 0.0037 |
| win_psexec_child_recon | 3 | yes | 0.0 % | 4 | 1.0000 | 1.0000 | 1.0000 / 1.0000 | 3,068,000 B | 7.0766 / 7.0766 |
| win_psexec_service | 1 | yes | 100.0 % | 4 | 1.0000 | – | 1.0000 / 1.0000 | 0 B | 0.0024 / 0.0024 |

## Cost model

Mean cost per hunt: full rehydration **10.68 USD**, this design **4.0433 USD** (by tier: T1 0.0024, T2 0.0090, T3 15.3419).

Extraction: one-time build 6.81 USD, plus derived-layer storage 701.14 USD/year. Hunts per year needed to pay for it: **105.5700** with this 7-day range, **0.4000** for the plan's 5-year hunts (full rehydration 2,787.52 vs 1,054.87 per hunt).

| Hunts per year (5-year range) | Full rehydration | This design |
|---|---|---|
| 1 | 2,787.52 | 1,756.02 |
| 10 | 27,875.24 | 11,249.87 |
| 50 | 139,376.18 | 53,444.79 |
| 100 | 278,752.36 | 106,188.45 |

Storage at modelled scale (6.923 TB raw, 4.565 TB derived): **65.45/month** (raw in deep archive + derived infrequent-access) vs 163.05/month for raw on standard storage (59.9 % less).

Estimate accuracy (|est − actual| / actual):

* uncalibrated: {"runs": 1, "mean": 0.0702, "median": 0.0702, "within_25pct": 1.0}
* calibrated: {"runs": 230, "mean": 0.1442, "median": 0.0, "within_25pct": 0.9739}

## Threat intelligence

* ti.tactical: 44 indicators ({"csv_blocklist": 5, "internal": 25, "threatfox": 7, "feodo": 2, "malwarebazaar": 4, "urlhaus": 3, "sslbl": 2, "cisa_kev": 2}), 36 sighted in the org
* ti.operational: 346 observations ({"llm": 146, "rule": 189, "feed_match": 11})
* ti.strategic tactics: command-and-control, credential-access, defense-evasion, discovery, execution, exfiltration, impact, initial-access, lateral-movement, persistence, privilege-escalation
* Feed retro-sweeps: 6, cost per indicator 0.0968 USD, feed-to-sighting latency {"median": 7.1, "max": 7.9} s, max sweep restore ratio 0.9 %

LLM mapping (offline/heuristic-v1): 9/9 planted scenarios mapped to at least one expected technique (or its parent).

| Scenario | Expected | Mapped | |
|---|---|---|---|
| s01-password-spray | T1110.003 | T1110.003 | ✅ |
| s02-brute-force | T1110.001 | T1110.001 | ✅ |
| s03-encoded-powershell | T1027, T1059.001, T1566.001 | T1027, T1059.001, T1071, T1105, T1197, T1204.002, T1218.005, T1218.011 | ✅ |
| s04-lolbins | T1105, T1197, T1218.005, T1218.011 | T1027, T1059.001, T1071, T1105, T1197, T1204.002, T1218.005, T1218.011 | ✅ |
| s05-lateral-movement | T1021.002, T1569.002 | T1021.002, T1033, T1087.002, T1569.002 | ✅ |
| s06-privilege-escalation | T1078.002, T1098 | T1078.002, T1098 | ✅ |
| s07-dns-tunnelling | T1048.003, T1071.004 | T1048.003, T1071.004 | ✅ |
| s08-exfiltration-burst | T1048, T1567.002 | T1048, T1567.002 | ✅ |
| s09-cryptomining | T1496 | T1027, T1059.001, T1496 | ✅ |

## Notes

* Recall is measured against the rule evaluated on *all* raw data (what a full rehydration answers), at entity × day for every tier and at event level where the tier returns events.
* Tier-2 correlation answers are sound over-approximations (upper-bound counts on hourly/daily buckets): they cannot miss an alert, but can add candidates; see label precision.
* Costs are modelled at `scale_factor` with the list prices in policies/pricing.yaml (verify them). In the prototype `actual_cost` prices the measured bytes; production would read billing exports.
* The offline LLM provider is a deterministic heuristic, so its mapping accuracy is a baseline; set LLM_PROVIDER=groq with GROQ_API_KEY and LLM_MODEL to measure a real model.
