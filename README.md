# Unified DNS Transaction Dataset — Step-by-Step Work Plan

## Purpose

This document breaks the unified DNS transaction-level dataset project into clear, executable steps.

The project uses **three PCAP-based datasets**:

```text
1. dns-tunnel-dataset-master - origin - Rotem
2. DNS-Tunnel-Datasets-main - origin - Nitsan
3. domainator-dataset-main - origin - Itamar
```

We are **not using** the separate `benign-dataset - origin - Internet` file.

The final base dataset will be:

```text
unified_dns_transactions.csv
```

Each row in this base dataset represents:

```text
one DNS query + its matched DNS response, if a response exists
```

From this unified transaction-level dataset, we will later create:

```text
flow_level_dataset.csv
window_sequence_dataset.csv
graph_window_dataset.csv
```

---

# Project Pipeline Overview

```text
Step 0  — Set project structure
Step 1  — Define the unified transaction schema
Step 2  — Build label rules for each dataset
Step 3  — Process Rotem dataset
Step 4  — Process Nitsan dataset
Step 5  — Process Itamar dataset
Step 6  — Validate each dataset separately
Step 7  — Combine the three transaction datasets
Step 8  — Validate the unified transaction dataset
Step 9  — Create flow-level dataset
Step 10 — Create window/sequence-level dataset
Step 11 — Create graph/window-level dataset
Step 12 — Run EDA and feature justification
Step 13 — Prepare ML-ready files and split strategy
```

---

# Step 0 — Set Project Structure

## Goal

Create a clean folder structure so every input, intermediate file, output file, and validation file is easy to find.

## Suggested folders

```text
project/
│
├── original data - all/
│   ├── dns-tunnel-dataset-master - origin - Rotem/
│   ├── DNS-Tunnel-Datasets-main - origin - Nitsan/
│   └── domainator-dataset-main - origin - Itamar/
│
├── outputs/
│   ├── 01_transactions_per_source/
│   ├── 02_unified_transactions/
│   ├── 03_derived_datasets/
│   ├── 04_validation_reports/
│   └── 05_eda/
│
├── scripts/
│   ├── extract_rotem_transactions.py
│   ├── extract_nitsan_transactions.py
│   ├── extract_itamar_transactions.py
│   ├── combine_transactions.py
│   ├── create_flow_dataset.py
│   ├── create_window_sequence_dataset.py
│   └── create_graph_window_dataset.py
│
└── documentation/
    ├── unified_dns_transaction_extraction_plan_steps.md
    ├── feature_dictionary.md
    └── split_strategy.md
```

## Output of this step

```text
Project folders are created.
Original datasets are placed in the correct folder.
```

## Done when

- All three dataset folders are visible under `original data - all`.
- There is a dedicated `outputs` folder.
- There is a dedicated `scripts` folder.

---

# Step 1 — Define the Unified Transaction Schema

## Goal

Before processing any dataset, define the exact columns that every dataset-specific extractor must output.

This prevents the three datasets from producing incompatible CSV files.

## Main output schema

Every source-specific transaction CSV must contain the same columns:

```text
source_name
source_type
dataset_id
source_archive
pcap_file
pcap_member_path
transaction_id
flow_id

traffic_label
tool_label
project_split
original_split
split_group_id
label_source

scenario_id
scenario_type
scenario_label
action_label
dns_server
dns_record_type
tunnel_encoding
tunnel_compression

client_ip
server_ip
client_port
server_port
transport_protocol
ip_version

request_packet_index
request_timestamp
request_len
request_payload_len
dns_id
query_name
query_name_normalized
query_type
query_class
base_domain
subdomain
domain_labels

response_packet_index
response_timestamp
response_len
response_payload_len
dns_rcode
dns_ancount
dns_nscount
dns_arcount
answer_records
authority_records
additional_records
ttl_values
min_ttl
max_ttl
mean_ttl
is_response_missing

query_name_len
subdomain_len
num_labels
max_label_len
query_entropy
longest_subdomain_entropy
long_consonant_string_count
req_resp_time_diff
total_transaction_bytes
is_dns
application_hint
is_doh_traffic
```

## Output of this step

```text
feature_dictionary.md
```

This file should explain each column, its type, and whether it is used for ML or only for traceability.

## Done when

- Every column is documented.
- We know which columns are labels.
- We know which columns are traceability-only and must not be used directly as model features.

---

# Step 2 — Define Label Rules for Each Dataset

## Goal

Each dataset has a different label structure, so label extraction must be source-specific.

The unified labels must be:

```text
traffic_label
tool_label
project_split
original_split
split_group_id
label_source
```

## General label rules

### Benign traffic

```text
traffic_label = benign
tool_label = benign
```

### Malicious traffic with known tool

```text
traffic_label = malicious
tool_label = actual tool name
```

### Malicious traffic with unknown tool

```text
traffic_label = malicious
tool_label = unknown
```

## Split values

```text
train
validation
test
external_test
unknown
```

## Important split rule

Never split randomly by transaction rows.

Always split by:

```text
split_group_id
```

Examples:

```text
Rotem  → scenario_id
Nitsan → PCAP / category / recording ID
Itamar → tool + scenario + PCAP / recording ID
```

## Output of this step

```text
split_strategy.md
label_rules.md
```

## Done when

- Each dataset has a clear label-mapping method.
- `project_split` logic is defined for each dataset.
- `split_group_id` is defined for each dataset.

---

# Step 3 — Process Rotem Dataset

## Source

```text
dns-tunnel-dataset-master - origin - Rotem
```

## Dataset facts

- Contains malicious DNS tunneling traffic.
- Contains 136 PCAP files.
- Previously extracted packet-level version had 3,031,952 DNS packet records.
- Tools: `iodine`, `dns2tcp`, `dnscat2`.
- Scenarios: file transfer over DNS tunnel and C2 over DNS tunnel.
- Does not contain a clear benign class.

## Goal

Create:

```text
dns_transactions_rotem.csv
```

## Label extraction

Labels should come from the README scenario tables.

### Scenario labels

| README section | `scenario_type` | `traffic_label` | `action_label` |
|---|---|---|---|
| File transfer over DNS Tunnel | `file_transfer` | `malicious` | `file_transfer` |
| C2 over DNS Tunnel | `c2` | `malicious` | `c2` |

### Tool labels

| README subsection | `tool_label` |
|---|---|
| IODINE | `iodine` |
| DNS2TCP | `dns2tcp` |
| DNSCAT | `dnscat2` |

## Rotem-specific metadata to preserve

```text
scenario_id
scenario_type
scenario_label
dns_server
dns_record_type
tunnel_encoding
tunnel_compression
automation_level
passphrase
```

## Transaction extraction logic

For each PCAP:

1. Parse packets.
2. Identify DNS query packets.
3. Match each query to its response using:
   - `dns_id`
   - IPs
   - ports
   - protocol
   - query name
   - query type
   - timestamp order
4. Create one transaction row per query.
5. If no response exists:
   - keep the query row
   - set `is_response_missing = 1`
6. Add labels using `scenario_id`.

## Split rule

```text
original_split = none
split_group_id = scenario_id
project_split = train / validation / test / external_test
```

Split manually by scenario ID, not by rows.

## Expected output files

```text
dns_transactions_rotem.csv
inventory_rotem.csv
label_summary_rotem.csv
error_log_rotem.csv
```

## Validation checklist

- Number of processed PCAPs.
- Number of transaction rows.
- Number of unknown scenario IDs.
- Tool distribution.
- Scenario distribution.
- Missing response ratio.
- Query type distribution.
- Missing values.

## Done when

- `dns_transactions_rotem.csv` exists.
- All rows have `traffic_label = malicious`.
- Tool labels are not empty.
- `label_summary_rotem.csv` looks reasonable.
- No major parsing errors appear in `error_log_rotem.csv`.

---

# Step 4 — Process Nitsan Dataset

## Source

```text
DNS-Tunnel-Datasets-main - origin - Nitsan
```

## Dataset facts

- GraphTunnel benchmark corpus.
- Raw PCAP files grouped by traffic categories.
- Contains both benign and malicious traffic.
- Total size: about 3,614,561 traffic records.
- Categories include:
  - `normal`
  - `tunnel`
  - `unknownTunnel`
  - `crossEndPoint`
  - `wildcard`

## Goal

Create:

```text
dns_transactions_nitsan.csv
```

## Label extraction

Labels should come from folder/category structure.

| Category | Meaning | Label handling |
|---|---|---|
| `normal` | normal benign DNS traffic | `traffic_label = benign`, `tool_label = benign` |
| `tunnel` | known DNS tunneling tools | `traffic_label = malicious`, tool from folder if available |
| `unknownTunnel` | unseen tunneling tools | `traffic_label = malicious`, `tool_label = unknown` or actual folder tool if available |
| `crossEndPoint` | Android/cross-endpoint tunneling | `traffic_label = malicious`, robustness/external test |
| `wildcard` | wildcard DNS evasion simulation | treat carefully; likely robustness/external test |

## Known tool groups

### Known tunnel pools

```text
dnscat2
dnspot
iodine
DNS-Shell
tuns
```

### Unknown tunnel pools

```text
tcp-over-dns
CobaltStrike
dns2tcp
OzymanDNS
```

### Cross-endpoint

```text
AndIodine
```

## Transaction extraction logic

For each PCAP:

1. Parse DNS packets.
2. Match query-response pairs.
3. Create one transaction row per DNS query.
4. Extract DNS lexical features.
5. Add category-based labels.
6. Add split metadata from folder structure if train/test exists.

## Split recommendation

```text
normal + known tunnel:
    train / validation / test

unknownTunnel:
    external_test or robustness test

crossEndPoint:
    external_test

wildcard:
    separate robustness test or external_test
```

## Recommended split group

```text
split_group_id = pcap_file or scenario/recording ID
```

## Expected output files

```text
dns_transactions_nitsan.csv
inventory_nitsan.csv
label_summary_nitsan.csv
error_log_nitsan.csv
```

## Validation checklist

- Check benign vs malicious counts.
- Confirm `normal` maps to benign.
- Confirm malicious categories map correctly.
- Check `unknownTunnel`, `crossEndPoint`, and `wildcard` handling.
- Check tool-label distribution.
- Check whether train/test folders exist and were captured as `original_split`.
- Check missing response ratio.
- Check query type distribution.

## Done when

- `dns_transactions_nitsan.csv` exists.
- It contains both `benign` and `malicious` in `traffic_label`.
- `normal` rows have `tool_label = benign`.
- Robustness categories are not accidentally used as normal training data.
- Label summary is reviewed manually.

---

# Step 5 — Process Itamar Dataset

## Source

```text
domainator-dataset-main - origin - Itamar
```

## Dataset facts

- Domainator dataset.
- Raw PCAP/PCAPNG network traffic captures.
- 89 PCAP/PCAPNG files.
- About 1,426,127 total packets.
- Extracted structured dataset contains about 365,960 DNS-query records.
- Mostly or only malicious traffic.
- No explicit benign/normal class in the downloaded repository.
- Best suited for tool classification and scenario/action classification.

## Goal

Create:

```text
dns_transactions_itamar.csv
```

## Tool labels

Original folder/family values may include:

```text
dnscat
iodine
roguerobin-net
roguerobin-powershell
saitama
symbiote
symbiote-dnscat
```

Recommended normalized values:

| Original folder/family | Normalized `tool_label` |
|---|---|
| `dnscat` | `dnscat2` or `dnscat` |
| `iodine` | `iodine` |
| `roguerobin-net` | `RogueRobin_NET` |
| `roguerobin-powershell` | `RogueRobin_PS` |
| `saitama` | `Saitama` |
| `symbiote` | `Symbiote` |
| `symbiote-dnscat` | `Symbiote_DNSCat2` |

Important decision:

> Choose either `dnscat` or `dnscat2` as the normalized label and use it consistently across all datasets.

Recommended for consistency with Rotem:

```text
dnscat → dnscat2
```

## Scenario/action labels

Original scenarios may include:

```text
handshake
handshake-fakenet
handshake-offline
idle
download
upload-big
upload-ssh-ed25519
upload-ssh-rsa4096
```

Recommended normalization:

| Original scenario | Normalized `action_label` |
|---|---|
| `handshake`, `handshake-fakenet`, `handshake-offline` | `handshake` |
| `idle` | `keep_alive` |
| `download` | `download` |
| `upload-big`, `upload-ssh-ed25519`, `upload-ssh-rsa4096` | `upload` |

## Transaction extraction logic

For each PCAP/PCAPNG:

1. Parse DNS packets.
2. Match query-response pairs.
3. Create one transaction row per DNS query.
4. Extract DNS lexical features.
5. Add tool label from folder/family.
6. Add scenario/action label from filename or scenario folder.
7. Mark validation/verification files as external test.

## Split recommendation

| Data part | `project_split` |
|---|---|
| Main tool recordings | `train` / `validation` / `test` |
| Validation / verification files | `external_test` |

## Recommended split group

```text
split_group_id = tool + scenario + pcap_file
```

## Expected output files

```text
dns_transactions_itamar.csv
inventory_itamar.csv
label_summary_itamar.csv
error_log_itamar.csv
```

## Validation checklist

- Count PCAP/PCAPNG files processed.
- Check tool distribution.
- Check action/scenario distribution.
- Confirm all rows are `traffic_label = malicious`.
- Confirm verification files are `project_split = external_test`.
- Check missing transport/port values.
- Check missing response ratio.
- Check unknown labels.

## Done when

- `dns_transactions_itamar.csv` exists.
- Tool labels are correctly normalized.
- Action labels are correctly normalized.
- Verification data is not in training.
- Label summary is reviewed manually.

---

# Step 6 — Validate Each Source Separately

## Goal

Before combining the datasets, verify that each source-specific transaction CSV is correct.

## Inputs

```text
dns_transactions_rotem.csv
dns_transactions_nitsan.csv
dns_transactions_itamar.csv
```

## Per-source validation checks

For each file, calculate:

| Check | Purpose |
|---|---|
| Row count | Confirm extraction size |
| PCAP count | Confirm coverage |
| `traffic_label` distribution | Verify benign/malicious labels |
| `tool_label` distribution | Verify tool mapping |
| `project_split` distribution | Verify split assignment |
| `original_split` distribution | Verify original split preservation |
| `scenario_type` distribution | Verify scenario mapping |
| Missing values by column | Identify unavailable fields |
| `is_response_missing` ratio | Understand query-response matching quality |
| `query_type` distribution | Detect unusual parsing issues |
| `dns_rcode` distribution | Validate response parsing |
| Unknown labels | Catch label extraction failures |

## Output files

```text
validation_rotem.csv
validation_nitsan.csv
validation_itamar.csv
```

or one report:

```text
source_validation_report.md
```

## Done when

- Each source file has the correct schema.
- Label distributions make sense.
- Unknown labels are investigated.
- Major parsing errors are fixed or documented.

---

# Step 7 — Combine the Three Transaction Datasets

## Goal

Create one unified transaction-level dataset from the three validated source datasets.

## Inputs

```text
dns_transactions_rotem.csv
dns_transactions_nitsan.csv
dns_transactions_itamar.csv
```

## Output

```text
unified_dns_transactions.csv
```

## Combining rules

1. Verify all files have the same columns.
2. Standardize column order.
3. Standardize label values.
4. Concatenate rows.
5. Preserve `source_name`.
6. Preserve `dataset_id`.
7. Preserve `split_group_id`.
8. Do not perform ML preprocessing yet.

## Done when

- `unified_dns_transactions.csv` exists.
- It contains rows from all three sources.
- Source distribution shows all three datasets.
- The schema is identical across all rows.

---

# Step 8 — Validate the Unified Transaction Dataset

## Goal

Check that the combined dataset is valid before deriving flow/window/graph datasets.

## Checks

| Check | Why |
|---|---|
| Total rows | Confirm successful combination |
| Source distribution | Ensure all datasets are included |
| Benign/malicious distribution | Check binary class balance |
| Tool distribution | Check multi-class imbalance |
| Split distribution | Check train/validation/test/external_test |
| Source vs label cross-tab | Detect leakage risk |
| Source vs split cross-tab | Ensure no source accidentally appears only in train |
| Missing values by source | Identify source-specific missingness |
| Query type distribution by source | Detect dataset artifacts |
| Response missing ratio by source | Check extraction consistency |
| Duplicate transaction IDs | Ensure uniqueness |
| Split-group leakage | Ensure same group not in multiple splits |

## Important limitation to check

Since the separate benign internet file is removed:

```text
Nitsan is the only benign source.
```

Therefore, check whether:

```text
all benign rows come only from Nitsan
```

This must be documented as a limitation.

## Output

```text
unified_validation_report.md
```

## Done when

- Unified dataset passes schema checks.
- No split group appears in more than one split.
- Class/source imbalance is documented.
- The limitation about Nitsan being the only benign source is documented.

---

# Step 9 — Create Flow-Level Dataset

## Goal

Create the first derived ML-ready dataset.

## Output

```text
flow_level_dataset.csv
```

## Input

```text
unified_dns_transactions.csv
```

## Granularity

```text
one row = one flow
```

## Group by

```text
source_name + pcap_file + flow_id
```

## Features to compute

| Feature group | Features |
|---|---|
| Flow metadata | `flow_start_time`, `flow_end_time`, `flow_duration`, `num_transactions`, `num_requests`, `num_responses` |
| Bytes | `total_bytes`, `bytes_sent`, `bytes_received`, `bytes_sent_rate`, `bytes_received_rate` |
| Request length stats | `mean_request_len`, `median_request_len`, `max_request_len`, `std_request_len` |
| Response length stats | `mean_response_len`, `median_response_len`, `max_response_len`, `std_response_len` |
| Total transaction bytes | `mean_total_transaction_bytes`, `median_total_transaction_bytes`, `max_total_transaction_bytes`, `std_total_transaction_bytes` |
| Timing stats | `mean_interarrival_time`, `median_interarrival_time`, `std_interarrival_time`, `queries_per_second` |
| Request-response timing | `mean_req_resp_time_diff`, `median_req_resp_time_diff`, `mode_req_resp_time_diff`, `var_req_resp_time_diff`, `std_req_resp_time_diff`, `cv_req_resp_time_diff`, `skew_from_median_req_resp_time_diff`, `skew_from_mode_req_resp_time_diff` |
| DNS response stats | `nxdomain_ratio`, `servfail_ratio`, `successful_response_ratio`, `missing_response_ratio` |

## Labels

Each flow inherits labels from the transactions inside it.

If a flow contains mixed labels, flag it for review.

## Done when

- `flow_level_dataset.csv` exists.
- Each row has `traffic_label`, `tool_label`, and `project_split`.
- Mixed-label flows are checked.
- Feature distributions are reviewed.

---

# Step 10 — Create Window / Sequence-Level Dataset

## Goal

Create the second derived ML-ready dataset, inspired by Domainator.

## Output

```text
window_sequence_dataset.csv
```

## Input

```text
unified_dns_transactions.csv
```

## Granularity

```text
one row = one sliding window of DNS requests under the same base domain
```

## Recommended parameters

```text
window_size = 10 DNS requests
minimum_window_size = 3 DNS requests
stride = 1
```

## Group by

```text
source_name + pcap_file + base_domain
```

## Sort by

```text
request_timestamp
```

## Features to compute

| Feature group | Features |
|---|---|
| Window metadata | `window_start_time`, `window_end_time`, `window_duration`, `window_size`, `num_requests`, `num_responses` |
| Query length stats | `mean_query_name_len`, `median_query_name_len`, `max_query_name_len`, `mean_subdomain_len`, `max_subdomain_len`, `mean_num_labels`, `max_num_labels`, `mean_max_label_len`, `max_label_len` |
| Entropy stats | `mean_query_entropy`, `max_query_entropy`, `mean_longest_subdomain_entropy`, `max_longest_subdomain_entropy` |
| Record-type stats | `count_A`, `count_AAAA`, `count_TXT`, `count_CNAME`, `count_MX`, `count_KEY`, `count_PRIVATE`, `count_NULL`, `ratio_A`, `ratio_TXT`, `ratio_CNAME`, `ratio_KEY`, `ratio_PRIVATE`, `ratio_NULL` |
| Timing stats | `mean_interarrival_time`, `median_interarrival_time`, `std_interarrival_time`, `queries_per_second` |
| Sequence similarity | `mean_levenshtein_distance`, `mean_jaro_similarity`, `mean_jaro_winkler_similarity`, `mean_longest_common_substring`, `mean_longest_common_subsequence`, `mean_jaro_reversed_similarity`, `mean_jaro_winkler_reversed_similarity` |
| Response stats | `missing_response_ratio`, `nxdomain_ratio`, `successful_response_ratio`, `mean_ttl`, `std_ttl` |

## Labels

A window inherits labels from the transactions inside it.

If a window contains mixed labels, flag it for review.

## Done when

- `window_sequence_dataset.csv` exists.
- Window size distribution is checked.
- Mixed-label windows are checked.
- Domainator-style similarity features are computed.
- Labels and splits are inherited correctly.

---

# Step 11 — Create Graph / Window-Level Dataset

## Goal

Create the third derived ML-ready dataset, inspired by GraphTunnel.

## Output

```text
graph_window_dataset.csv
```

## Input

```text
unified_dns_transactions.csv
```

## Granularity

```text
one row = one graph/window of DNS resolution behavior
```

## Recommended starting value

```text
K = 20 query paths / transactions per graph window
```

## Graph construction

If full recursive-resolution visibility exists, create recursive DNS path graphs.

If not, create simplified graph/window features using:

```text
client_ip
server_ip
base_domain
query_name
query_type
dns_rcode
req_resp_time_diff
ttl values
```

## Features to compute

| Feature group | Features |
|---|---|
| Graph metadata | `graph_start_time`, `graph_end_time`, `num_paths`, `num_nodes`, `num_edges` |
| Domain/node statistics | `num_unique_domains`, `num_unique_subdomains`, `num_unique_base_domains`, `num_unique_query_types` |
| Lexical node statistics | `mean_subdomain_len`, `max_subdomain_len`, `mean_max_label_len`, `max_label_len`, `mean_entropy`, `max_entropy`, `mean_long_consonant_string_count` |
| DNS response statistics | `mean_ttl`, `median_ttl`, `min_ttl`, `max_ttl`, `std_ttl`, `nxdomain_ratio`, `successful_response_ratio` |
| Edge/timing statistics | `num_request_response_pairs`, `mean_response_time`, `median_response_time`, `std_response_time`, `orphan_request_count`, `orphan_response_count` |
| Graph structure statistics | `avg_node_degree`, `max_node_degree`, `domain_reuse_ratio` |

## Labels

A graph window inherits labels from the transactions inside it.

If a graph window contains mixed labels, flag it for review.

## Done when

- `graph_window_dataset.csv` exists.
- Graph/window construction logic is documented.
- Graph feature distributions are checked.
- Labels and splits are inherited correctly.

---

# Step 12 — Run EDA and Feature Justification

## Goal

Use statistics and plots to justify the chosen features.

This is required for the workshop.

## EDA must include

For each derived dataset:

```text
flow_level_dataset.csv
window_sequence_dataset.csv
graph_window_dataset.csv
```

Run:

1. Class distribution.
2. Tool distribution.
3. Split distribution.
4. Feature missingness.
5. Feature distributions by benign/malicious.
6. Feature distributions by tool.
7. Correlation matrix.
8. Redundant feature detection.
9. Feature leakage checks.
10. Source-vs-label analysis.

## Important EDA questions

- Do malicious queries have higher entropy?
- Do malicious queries have longer query names?
- Do malicious windows have different query-type ratios?
- Are timing patterns different between benign and malicious?
- Are models likely to learn source artifacts instead of attack behavior?
- Are `query_name_len` and `num_labels` too highly correlated?
- Are some features constant in some sources?

## Output

```text
eda_report.ipynb
eda_summary.md
```

## Done when

- Every proposed feature has a data-driven justification.
- Redundant/noisy features are identified.
- Leakage-prone fields are excluded from ML feature vectors.
- Dataset limitations are clearly documented.

---

# Step 13 — Prepare ML-Ready Files and Split Strategy

## Goal

Prepare final model-input files for training.

## For each derived dataset

Create:

```text
X_features.csv
y_binary.csv
y_tool.csv
split_file.csv
```

or keep one table with:

```text
features + traffic_label + tool_label + project_split
```

## Columns to drop before model training

Do not use these as direct model features:

```text
source_name
source_type
dataset_id
source_archive
pcap_file
pcap_member_path
transaction_id
flow_id
client_ip
server_ip
request_packet_index
response_packet_index
request_timestamp
response_timestamp
label_source
```

They may be kept for traceability and error analysis, but not as model inputs.

## Model tasks

### Task 1 — Binary detection

Target:

```text
traffic_label
```

Classes:

```text
benign
malicious
```

Important limitation:

```text
Nitsan is the only benign source.
```

### Task 2 — Tool classification

Target:

```text
tool_label
```

Use mostly malicious traffic.

A clean setup:

```text
Model 1: benign vs malicious
Model 2: if malicious, classify tool
```

## Done when

- Final feature lists are defined.
- Labels are clean.
- Splits are clean.
- No split-group leakage exists.
- ML training can begin.

---

# Final Checklist

Use this checklist to track progress.

| Step | Task | Status |
|---:|---|---|
| 0 | Set project folder structure | Not started |
| 1 | Define unified transaction schema | Not started |
| 2 | Define label rules and split strategy | Not started |
| 3 | Process Rotem dataset | Not started |
| 4 | Process Nitsan dataset | Not started |
| 5 | Process Itamar dataset | Not started |
| 6 | Validate each source separately | Not started |
| 7 | Combine transaction datasets | Not started |
| 8 | Validate unified transaction dataset | Not started |
| 9 | Create flow-level dataset | Not started |
| 10 | Create window/sequence-level dataset | Not started |
| 11 | Create graph/window-level dataset | Not started |
| 12 | Run EDA and feature justification | Not started |
| 13 | Prepare ML-ready files | Not started |

---

# Final Summary

The project should be executed in this order:

```text
1. Create one transaction-level CSV per source.
2. Validate each source separately.
3. Combine into unified_dns_transactions.csv.
4. Validate the unified dataset.
5. Derive flow/window/graph datasets.
6. Run EDA.
7. Prepare ML-ready data.
8. Train models.
```

This structure keeps the work organized, prevents label mistakes, reduces leakage, and lets us compare different granularities cleanly.
