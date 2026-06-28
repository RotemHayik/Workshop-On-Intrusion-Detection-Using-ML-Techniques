# Workshop-On-Intrusion-Detection-Using-ML-Techniques
# Unified PCAP Extraction Plan for DNS Tunneling Detection

## Purpose

This document defines the data-preservation and feature-extraction plan for our AI-driven intrusion detection workshop project.

Our project combines three original PCAP-based datasets related to DNS tunneling / C2 over DNS. Because the reviewed academic papers analyze DNS tunneling at different granularities, we will first extract a unified **packet-level raw table** from all PCAP files. From that preserved base table, we will later generate three ML-ready dataset versions:

1. **Flow-level dataset** — inspired mainly by the DoH hierarchical classification paper.
2. **Window / sequence-level dataset** — inspired mainly by Domainator.
3. **Graph / window-level dataset** — inspired mainly by GraphTunnel.

The goal is to parse the PCAPs only once, preserve all fields needed for future feature engineering, and keep the downstream ML pipeline reproducible.

---

## Academic basis

### Paper 1 — GraphTunnel

**Paper:** *GraphTunnel: Robust DNS Tunnel Detection Based on DNS Recursive Resolution Graph*

Main idea:
GraphTunnel filters DNS traffic, parses DNS request/response information, constructs DNS recursive-resolution paths, and then builds graph representations for DNS tunnel detection and tunneling-tool identification.

Implication for our extraction:
We must preserve DNS packet fields such as query name, query type, DNS response information, TTL, packet size, timestamps, and request-response matching information.

Important raw needs:
- DNS query / response flag
- query name
- query type
- TTL
- packet length
- timestamps
- request-response relationship
- response records
- fields that allow graph/window construction

---

### Paper 2 — Domainator

**Paper:** *Domainator: Detecting and Identifying DNS-Tunneling Malware Using Metadata Sequences*

Main idea:
Domainator analyzes DNS request sequences under the same domain. It uses a sliding window of DNS requests and computes statistical similarity metrics over subdomain strings.

Implication for our extraction:
We must preserve the ordered sequence of DNS queries, especially the query name and packet timestamp. The packet order must be stable so that later windows preserve the true communication sequence.

Important raw needs:
- packet index
- timestamp
- query name
- query type
- DNS request/response direction
- base domain / domain grouping can be derived later from query name
- labels for malware/tool and action when available

---

### Paper 3 — DoH Hierarchical Classification

**Paper:** *Identifying Malicious DNS Tunnel Tools from DoH Traffic Using Hierarchical Machine Learning Classification*

We will use only:

- **Stage 2:** normal DoH vs suspicious/malicious DoH
- **Stage 3:** malicious DNS tunnel tool identification

Main idea:
Because DoH is encrypted, the method does not rely on DNS payload fields. It extracts flow-level statistical features from HTTPS/DoH packet metadata: packet lengths, packet timing, flow direction, and request/response timing.

Implication for our extraction:
Even when DNS payload is not visible, we must preserve general network metadata for every packet.

Important raw needs:
- timestamp
- packet length
- source/destination IP
- source/destination port
- protocol
- flow ID
- packet direction
- TCP stream or session identifier when available

---

## Overall dataset strategy

We will create:

```text
Raw PCAP files
    ↓
packet_level_raw.csv
    ↓
flow_level_dataset.csv
window_sequence_dataset.csv
graph_window_dataset.csv
```

The **packet-level raw CSV** is the preservation layer.  
The other three files are ML-ready views derived from it.

This means we do not lose information when experimenting with different modeling approaches.

---

# 1. Base extraction file: `packet_level_raw.csv`

## Granularity

Each row represents:

```text
one packet from one PCAP file
```

This table is not necessarily the final ML table. It is the canonical raw extraction table.

---

## 1.1 Metadata fields

These fields preserve where each packet came from.

| Field name | Type | Description | Required? |
|---|---:|---|---|
| `dataset_id` | string | Name of the source dataset | Yes |
| `pcap_file` | string | Original PCAP filename or relative path | Yes |
| `packet_index` | integer | Packet number inside the PCAP, preserving original order | Yes |
| `timestamp_epoch` | float | Packet timestamp as Unix epoch | Yes |
| `timestamp_iso` | string | Human-readable timestamp, optional but useful for debugging | Recommended |
| `capture_source` | string | Optional source description, for example lab, CIC, DoH, etc. | Optional |

Why needed:
- Supports reproducibility.
- Allows tracing every derived sample back to original PCAP packets.
- Preserves temporal order for window and sequence construction.

---

## 1.2 Basic network fields

These are required by all three approaches.

| Field name | Type | Description | Required? |
|---|---:|---|---|
| `packet_len` | integer | Full packet length in bytes | Yes |
| `src_ip` | string | Source IP address | Yes |
| `dst_ip` | string | Destination IP address | Yes |
| `ip_version` | integer | IPv4 = 4, IPv6 = 6 | Recommended |
| `transport_protocol` | string | UDP, TCP, TLS/HTTPS if identifiable | Yes |
| `src_port` | integer | Source transport-layer port | Yes |
| `dst_port` | integer | Destination transport-layer port | Yes |
| `flow_id` | string | Canonical flow identifier | Yes |
| `packet_direction` | string | Direction within the flow: `client_to_server`, `server_to_client`, or `unknown` | Yes |
| `tcp_stream_id` | string/integer | TCP stream/session ID when available | Recommended for DoH |
| `udp_conversation_id` | string/integer | UDP conversation ID when available | Recommended |

Why needed:
- Flow-level dataset requires grouping packets by flow.
- DoH features require packet lengths, packet times, and packet direction.
- Direction is needed for sent/received byte statistics and request-response timing.

Suggested `flow_id` construction:

```text
protocol + min(src_ip:src_port, dst_ip:dst_port) + max(src_ip:src_port, dst_ip:dst_port)
```

This creates a direction-independent flow key.

---

## 1.3 DNS packet fields

These fields are available for plain DNS traffic. For encrypted DoH traffic, these fields will usually be null.

| Field name | Type | Description | Required? |
|---|---:|---|---|
| `is_dns` | integer | 1 if packet is parsed as DNS, else 0 | Yes |
| `dns_id` | integer/string | DNS transaction ID | Yes when available |
| `dns_qr` | integer | DNS query/response flag: 0 = query, 1 = response | Yes when available |
| `dns_opcode` | integer/string | DNS opcode | Recommended |
| `dns_rcode` | integer/string | DNS response code | Yes when available |
| `dns_qdcount` | integer | Number of DNS questions | Recommended |
| `dns_ancount` | integer | Number of answers | Recommended |
| `dns_nscount` | integer | Number of authority records | Recommended |
| `dns_arcount` | integer | Number of additional records | Recommended |
| `query_name` | string | Full DNS query name | Yes when available |
| `query_type` | string | DNS record type: A, AAAA, TXT, CNAME, MX, NULL, etc. | Yes when available |
| `query_class` | string | Usually IN | Recommended |
| `answer_records` | string/json | Parsed answer records, stored compactly | Recommended |
| `authority_records` | string/json | Parsed authority records | Recommended |
| `additional_records` | string/json | Parsed additional records | Recommended |
| `ttl_values` | string/list | TTL values from response records | Yes when available |
| `min_ttl` | integer/float | Minimum TTL in packet response | Recommended |
| `max_ttl` | integer/float | Maximum TTL in packet response | Recommended |
| `mean_ttl` | float | Mean TTL in packet response | Recommended |

Why needed:
- GraphTunnel requires query type, domain lexical fields, TTL, packet size, and response timing.
- Domainator requires query names and their order.
- DNS response statistics are useful for detecting failed queries, NXDOMAIN behavior, and suspicious record patterns.

---

## 1.4 Domain string preservation fields

These are still raw or lightly parsed fields. More advanced statistics will be computed later.

| Field name | Type | Description | Required? |
|---|---:|---|---|
| `query_name_normalized` | string | Lowercased query name without trailing dot | Recommended |
| `base_domain` | string | Registered/base domain if extraction is reliable | Recommended |
| `subdomain` | string | Part before the base domain | Recommended |
| `domain_labels` | string/list | Labels split by dot | Optional |
| `top_private_domain_parse_status` | string | Indicates whether base-domain extraction succeeded | Optional |

Why needed:
- Domainator windows are grouped by domain.
- GraphTunnel and DNS lexical features need subdomain extraction.
- Keeping normalized and parsed versions helps avoid recomputing expensive parsing.

Important note:
If base-domain extraction is uncertain, preserve the original `query_name` and mark the parse status rather than overwriting values.

---

## 1.5 Payload / parsing fallback fields

| Field name | Type | Description | Required? |
|---|---:|---|---|
| `raw_payload_len` | integer | Length of transport payload | Recommended |
| `raw_payload_hex_prefix` | string | Short prefix only, for debugging parsing issues | Optional |
| `dns_parse_error` | string | Error message or code if DNS parsing failed | Recommended |
| `has_dns_layer` | integer | 1 if parser found DNS layer, else 0 | Recommended |
| `application_hint` | string | Optional hint such as DNS, DoH, HTTPS, other | Optional |

Why needed:
- GraphTunnel mentions fallback parsing for raw layer cases where DNS headers may be missing or parsing fails.
- DoH traffic is encrypted, so raw DNS payload will not be available, but packet metadata still matters.
- Parse errors must be preserved for debugging.

Privacy note:
Do not store full payload unless required. For preservation, metadata and short prefixes are usually safer.

---

# 2. Label fields in `packet_level_raw.csv`

Labels should be attached as early as possible so that all derived datasets inherit them.

| Label field | Values | Description |
|---|---|---|
| `traffic_label` | `benign`, `malicious` | Main binary target |
| `tool_label` | `benign`, `iodine`, `dnscat2`, `dns2tcp`, `RogueRobin_PS`, `RogueRobin_NET`, `Saitama`, `Symbiote`, `Symbiote_DNSCat2`, etc. | Tool or malware family |
| `action_label` | `benign`, `handshake`, `keep_alive`, `upload`, `download`, `c2`, `file_transfer`, `unknown` | Malware behavior/action when known |
| `scenario_label` | dataset-specific | Scenario name from original dataset |
| `split_hint` | `train`, `validation`, `test`, or blank | Optional fixed split if provided by dataset |
| `label_source` | string | How label was obtained: folder name, metadata file, scenario config, manual mapping, etc. |

Label rules:

For benign traffic:

```text
traffic_label = benign
tool_label = benign
action_label = benign
```

For malicious traffic with known tool:

```text
traffic_label = malicious
tool_label = actual tool name
action_label = known action if available, otherwise unknown
```

For malicious traffic where the tool is unknown:

```text
traffic_label = malicious
tool_label = unknown
action_label = known action if available, otherwise unknown
```

---

# 3. Derived dataset 1: `flow_level_dataset.csv`

## Purpose

This version is designed for the DoH hierarchical classification approach, using only Stage 2 and Stage 3:

- Stage 2: benign/normal DoH vs malicious/suspicious DoH
- Stage 3: malicious tool identification

## Granularity

Each row represents:

```text
one bidirectional network flow
```

## Built from packet-level fields

Required packet fields:
- `timestamp_epoch`
- `packet_len`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `transport_protocol`
- `flow_id`
- `packet_direction`
- `tcp_stream_id`

## Features to compute later

| Feature group | Derived features |
|---|---|
| Flow metadata | `flow_start_time`, `flow_end_time`, `flow_duration`, `num_packets` |
| Bytes | `flow_bytes_sent`, `flow_bytes_received`, `bytes_sent_rate`, `bytes_received_rate` |
| Packet length statistics | `mean_packet_len`, `median_packet_len`, `mode_packet_len`, `var_packet_len`, `std_packet_len`, `cv_packet_len`, `skew_from_median_packet_len`, `skew_from_mode_packet_len` |
| Packet timing statistics | `mean_packet_time`, `median_packet_time`, `mode_packet_time`, `var_packet_time`, `std_packet_time`, `cv_packet_time`, `skew_from_median_packet_time`, `skew_from_mode_packet_time` |
| Request/response timing | `mean_req_resp_time_diff`, `median_req_resp_time_diff`, `mode_req_resp_time_diff`, `var_req_resp_time_diff`, `std_req_resp_time_diff`, `cv_req_resp_time_diff`, `skew_from_median_req_resp_time_diff`, `skew_from_mode_req_resp_time_diff` |

Labels:
- `traffic_label`
- `tool_label`
- `dataset_id`
- `scenario_label`

---

# 4. Derived dataset 2: `window_sequence_dataset.csv`

## Purpose

This version is designed for the Domainator-style sequence approach.

## Granularity

Each row represents:

```text
one sliding window of DNS requests under the same base domain
```

Recommended initial parameters:

```text
window_size = 10 DNS requests
minimum_window_size = 3 DNS requests
stride = 1 or configurable
```

## Built from packet-level fields

Required packet fields:
- `packet_index`
- `timestamp_epoch`
- `query_name`
- `query_name_normalized`
- `base_domain`
- `subdomain`
- `query_type`
- `dns_qr`
- `flow_id`
- `packet_len`

## Features to compute later

| Feature group | Derived features |
|---|---|
| Window metadata | `window_start_time`, `window_end_time`, `window_duration`, `window_size`, `num_requests`, `num_responses` |
| Query length statistics | `mean_query_name_len`, `median_query_name_len`, `max_query_name_len`, `mean_subdomain_len`, `max_subdomain_len`, `mean_num_labels`, `max_num_labels`, `mean_max_label_len`, `max_label_len` |
| Entropy statistics | `mean_query_entropy`, `max_query_entropy`, `mean_longest_subdomain_entropy`, `max_longest_subdomain_entropy` |
| Record type statistics | `count_A`, `count_AAAA`, `count_TXT`, `count_CNAME`, `count_MX`, `count_NULL`, `count_PRIVATE`, `ratio_A`, `ratio_TXT`, `ratio_CNAME`, `ratio_NULL_PRIVATE` |
| Timing statistics | `mean_interarrival_time`, `median_interarrival_time`, `std_interarrival_time`, `queries_per_second` |
| Sequence similarity | `mean_levenshtein_distance`, `mean_jaro_similarity`, `mean_jaro_winkler_similarity`, `mean_longest_common_substring`, `mean_longest_common_subsequence`, `mean_jaro_reversed_similarity`, `mean_jaro_winkler_reversed_similarity` |

Labels:
- `traffic_label`
- `tool_label`
- `action_label`
- `dataset_id`
- `scenario_label`

---

# 5. Derived dataset 3: `graph_window_dataset.csv`

## Purpose

This version is designed for a GraphTunnel-inspired representation.

## Granularity

Each row represents:

```text
one graph/window of DNS resolution behavior
```

If full recursive resolver visibility exists:

```text
one graph = K recursive DNS query paths
```

Recommended starting value:

```text
K = 20 query paths
```

If full recursive visibility does not exist, use an approximate graph/window built from:
- domains
- query-response pairs
- base domains
- flow relationships
- response behavior

## Built from packet-level fields

Required packet fields:
- `timestamp_epoch`
- `packet_len`
- `src_ip`
- `dst_ip`
- `flow_id`
- `dns_id`
- `dns_qr`
- `query_name`
- `query_type`
- `ttl_values`
- `dns_rcode`
- `answer_records`
- `authority_records`
- `additional_records`

## Features to compute later

| Feature group | Derived features |
|---|---|
| Graph metadata | `graph_start_time`, `graph_end_time`, `num_paths`, `num_nodes`, `num_edges` |
| Domain/node statistics | `num_unique_domains`, `num_unique_subdomains`, `num_unique_base_domains`, `num_unique_query_types` |
| Lexical node statistics | `mean_subdomain_len`, `max_subdomain_len`, `mean_max_label_len`, `max_label_len`, `mean_entropy`, `max_entropy`, `mean_long_consonant_string_count` |
| DNS response statistics | `mean_ttl`, `median_ttl`, `min_ttl`, `max_ttl`, `std_ttl`, `nxdomain_ratio`, `successful_response_ratio` |
| Edge/timing statistics | `num_request_response_pairs`, `mean_response_time`, `median_response_time`, `std_response_time`, `orphan_request_count`, `orphan_response_count` |
| Graph structure statistics | `avg_node_degree`, `max_node_degree`, `domain_reuse_ratio` |

Labels:
- `traffic_label`
- `tool_label`
- `action_label`
- `dataset_id`
- `scenario_label`

---

# 6. Extraction workflow

## Step 1 — Inventory all PCAP sources

For each original dataset, create a metadata table:

| Field | Meaning |
|---|---|
| `dataset_id` | Dataset name |
| `pcap_file` | PCAP path |
| `traffic_label` | benign/malicious |
| `tool_label` | tool/malware name |
| `action_label` | action/scenario if known |
| `scenario_label` | original scenario |
| `notes` | assumptions or caveats |

Output:

```text
pcap_inventory.csv
```

---

## Step 2 — Parse each PCAP into packet-level rows

For each packet:

1. Save metadata: dataset, file, packet index, timestamp.
2. Extract network fields: IPs, ports, protocol, packet length.
3. Build flow ID and packet direction.
4. If DNS is visible, parse DNS fields.
5. If DNS parsing fails, preserve parse status and minimal raw payload metadata.
6. Attach labels from inventory or dataset metadata.

Output:

```text
packet_level_raw.csv
```

---

## Step 3 — Validate packet-level extraction

Checks to run:

| Check | Goal |
|---|---|
| Missing values by column | Identify fields unavailable in some datasets |
| Label distribution | Verify benign/malicious and tool labels |
| PCAP coverage | Confirm all files were processed |
| DNS parse rate | Check how many packets were parsed as DNS |
| Flow count | Verify flow grouping |
| Timestamp order | Confirm packet ordering is preserved |
| Duplicate packet rows | Avoid accidental duplication |
| Constant columns | Find useless features |
| Dataset-specific artifacts | Identify leakage-prone columns |

---

## Step 4 — Build derived datasets

From `packet_level_raw.csv`, generate:

```text
flow_level_dataset.csv
window_sequence_dataset.csv
graph_window_dataset.csv
```

Each derived dataset must preserve:
- `sample_id`
- `dataset_id`
- `pcap_file`
- target labels
- enough traceability columns to map back to raw packets

---

## Step 5 — Run EDA per derived dataset

For each dataset version:

1. Compare benign vs malicious distributions.
2. Compare tool-label distributions.
3. Plot feature distributions.
4. Compute correlations.
5. Identify redundant features.
6. Identify dataset-specific bias.
7. Test normalization/scaling needs.
8. Check for data leakage.

---

## Step 6 — Train models per granularity version

Use the same modular pipeline structure:

```text
Data Ingestion
→ Preprocessing & Normalization
→ Feature Selection & Engineering
→ Model Training
→ Evaluation
```

The ingestion module can choose one of:

```text
flow
window_sequence
graph_window
```

All later pipeline stages should be dataset-agnostic.

---

# 7. Columns not to use directly as model features

These fields are useful for traceability but should usually be excluded from model training to avoid leakage:

| Field | Why exclude |
|---|---|
| `dataset_id` | Model may learn dataset source instead of behavior |
| `pcap_file` | Strong leakage risk |
| `packet_index` | May encode scenario order |
| `timestamp_epoch` | May encode collection artifact |
| `timestamp_iso` | Same as above |
| `src_ip` | May encode lab setup |
| `dst_ip` | May encode lab setup |
| `flow_id` | Identifier, not behavior |
| `sample_id` | Identifier |
| `label_source` | Direct leakage |

These fields should remain in files for error analysis, but must be dropped before training unless there is a clear reason not to.

---

# 8. Final output files

| File | Purpose |
|---|---|
| `pcap_inventory.csv` | Maps PCAPs to labels and metadata |
| `packet_level_raw.csv` | Canonical packet-level preservation table |
| `flow_level_dataset.csv` | ML-ready flow-level dataset |
| `window_sequence_dataset.csv` | ML-ready DNS sequence-window dataset |
| `graph_window_dataset.csv` | ML-ready graph/window dataset |
| `feature_dictionary.md` | Human-readable explanation of all raw and derived fields |
| `eda_report.ipynb` | Statistical validation and feature justification |
| `pipeline_config.yaml` | Config file controlling granularity and feature sets |

---

# 9. Summary

Our data strategy is:

```text
Combine all original PCAP datasets
→ Extract one unified packet-level raw schema
→ Preserve all raw telemetry required by the three papers
→ Derive three ML-ready versions at different granularities
→ Run the same modular ML pipeline over each version
→ Compare which granularity best detects DNS tunneling and identifies tools
```

This gives us both:
- a strong preservation layer for future work, and
- flexible ML-ready datasets aligned with the academic literature.
