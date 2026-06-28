import os
import math
import uuid
import collections
import pandas as pd
from datetime import datetime
from scapy.all import rdpcap, IP, IPv6, UDP, TCP, DNS, DNSQR, DNSRR

# Define the exact schema from Step 1
SCHEMA_COLUMNS = [
    "source_name", "source_type", "dataset_id", "source_archive", "pcap_file",
    "pcap_member_path", "transaction_id", "flow_id", "traffic_label", "tool_label",
    "project_split", "original_split", "split_group_id", "label_source",
    "scenario_id", "scenario_type", "scenario_label", "action_label", "dns_server",
    "dns_record_type", "tunnel_encoding", "tunnel_compression", "client_ip", "server_ip",
    "client_port", "server_port", "transport_protocol", "ip_version",
    "request_packet_index", "request_timestamp", "request_len", "request_payload_len",
    "dns_id", "query_name", "query_name_normalized", "query_type", "query_class",
    "base_domain", "subdomain", "domain_labels", "response_packet_index",
    "response_timestamp", "response_len", "response_payload_len", "dns_rcode",
    "dns_ancount", "dns_nscount", "dns_arcount", "answer_records", "authority_records",
    "additional_records", "ttl_values", "min_ttl", "max_ttl", "mean_ttl",
    "is_response_missing", "query_name_len", "subdomain_len", "num_labels",
    "max_label_len", "query_entropy", "longest_subdomain_entropy",
    "long_consonant_string_count", "req_resp_time_diff", "total_transaction_bytes",
    "is_dns", "application_hint", "is_doh_traffic"
]

# Helper function to calculate Shannon Entropy
def calculate_entropy(text):
    if not text:
        return 0.0
    text = str(text)
    frequencies = collections.Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())

# Helper function to count consecutive consonant sequences
def count_long_consonants(text, threshold=4):
    if not text:
        return 0
    consonants = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ"
    max_count = 0
    current_count = 0
    for char in text:
        if char in consonants:
            current_count += 1
            if current_count >= threshold:
                max_count += 1
        else:
            current_count = 0
    return max_count

# Parse Domain breakdown helper
def parse_domain_details(qname):
    if not qname:
        return "", "", 0, 0
    qname = qname.decode('utf-8', errors='ignore').rstrip('.') if isinstance(qname, bytes) else str(qname).rstrip('.')
    labels = qname.split('.')
    num_labels = len(labels)
    max_label_len = max([len(l) for l in labels]) if labels else 0
    
    if num_labels >= 2:
        base_domain = f"{labels[-2]}.{labels[-1]}"
        subdomain = ".".join(labels[:-2])
    else:
        base_domain = qname
        subdomain = ""
        
    return base_domain, subdomain, num_labels, max_label_len

# Map categories according to step 4 specs
def resolve_labels_and_splits(filepath):
    parts = filepath.replace("\\", "/").split("/")
    
    # Defaults
    traffic_label = "malicious"
    tool_label = "unknown"
    project_split = "train"
    
    # Infer rules based on directory tree naming
    category = "unknown"
    for p in parts:
        if p in ["normal", "tunnel", "unknownTunnel", "crossEndPoint", "wildcard"]:
            category = p
            break
            
    if category == "normal":
        traffic_label = "benign"
        tool_label = "benign"
        project_split = "train"
    elif category == "tunnel":
        traffic_label = "malicious"
        # Extract specific tools from path if matched
        for tool in ["dnscat2", "dnspot", "iodine", "DNS-Shell", "tuns"]:
            if any(tool.lower() in p.lower() for p in parts):
                tool_label = tool
                break
    elif category == "unknownTunnel":
        traffic_label = "malicious"
        tool_label = "unknown"
        for tool in ["tcp-over-dns", "CobaltStrike", "dns2tcp", "OzymanDNS"]:
            if any(tool.lower() in p.lower() for p in parts):
                tool_label = tool
                break
        project_split = "external_test"
    elif category in ["crossEndPoint", "wildcard"]:
        traffic_label = "malicious"
        tool_label = "AndIodine" if category == "crossEndPoint" else "wildcard_simulation"
        project_split = "external_test"

    return traffic_label, tool_label, project_split

def process_pcap(pcap_path, base_dir):
    relative_pcap_path = os.path.relpath(pcap_path, base_dir)
    traffic_label, tool_label, project_split = resolve_labels_and_splits(relative_pcap_path)
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")
        return []

    queries = {}
    transactions = []
    
    for idx, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(DNS):
            continue
            
        # Determine Network Protocols
        ip_version = "unknown"
        src_ip, dst_ip = "0.0.0.0", "0.0.0.0"
        if pkt.haslayer(IP):
            ip_version = "4"
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            ip_version = "6"
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
            
        # Transport Layer
        transport_protocol = "unknown"
        src_port, dst_port = 0, 0
        if pkt.haslayer(UDP):
            transport_protocol = "UDP"
            src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
        elif pkt.haslayer(TCP):
            transport_protocol = "TCP"
            src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
            
        dns_layer = pkt[DNS]
        dns_id = dns_layer.id
        
        # Flow Identification Key (standard 5-tuple)
        flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{transport_protocol}"
        
        # --- DNS QUERY HANDLING ---
        if dns_layer.qr == 0:
            qname_str = ""
            qtype = 0
            qclass = 0
            
            if dns_layer.qdcount > 0 and dns_layer.qd:
                qname = getattr(dns_layer.qd, 'qname', b"")
                qtype = getattr(dns_layer.qd, 'qtype', 0)
                qclass = getattr(dns_layer.qd, 'qclass', 0)
                qname_str = qname.decode('utf-8', errors='ignore').rstrip('.') if isinstance(qname, bytes) else str(qname).rstrip('.')
            
            base_domain, subdomain, num_labels, max_label_len = parse_domain_details(qname_str)
            match_key = (dns_id, src_ip, dst_ip, src_port, dst_port, qname_str, qtype)
            
            query_info = {
                "request_packet_index": idx,
                "request_timestamp": float(pkt.time),
                "request_len": len(pkt),
                "request_payload_len": len(dns_layer),
                "dns_id": dns_id,
                "query_name": qname_str,
                "query_name_normalized": qname_str.lower(),
                "query_type": qtype,
                "query_class": qclass,
                "base_domain": base_domain,
                "subdomain": subdomain,
                "domain_labels": str(qname_str.split('.')),
                "client_ip": src_ip,
                "server_ip": dst_ip,
                "client_port": src_port,
                "server_port": dst_port,
                "transport_protocol": transport_protocol,
                "ip_version": ip_version,
                "flow_id": flow_id,
                "query_name_len": len(qname_str),
                "subdomain_len": len(subdomain),
                "num_labels": num_labels,
                "max_label_len": max_label_len,
                "query_entropy": calculate_entropy(qname_str),
                "longest_subdomain_entropy": calculate_entropy(max(subdomain.split('.'), key=len)) if subdomain else 0.0,
                "long_consonant_string_count": count_long_consonants(qname_str)
            }
            queries[match_key] = query_info
            
        # --- DNS RESPONSE HANDLING ---
        elif dns_layer.qr == 1:
            qname_resp_str = ""
            qtype_resp = 0
            
            if dns_layer.qdcount > 0 and dns_layer.qd:
                qname_resp = getattr(dns_layer.qd, 'qname', b"")
                qtype_resp = getattr(dns_layer.qd, 'qtype', 0)
                qname_resp_str = qname_resp.decode('utf-8', errors='ignore').rstrip('.') if isinstance(qname_resp, bytes) else str(qname_resp).rstrip('.')
            
            # Responses reverse the IP/Port configurations compared to queries
            match_key = (dns_id, dst_ip, src_ip, dst_port, src_port, qname_resp_str, qtype_resp)
            
            # Parse TTLs
            ttls = []
            if dns_layer.ancount > 0 and dns_layer.an:
                curr_layer = dns_layer.an
                while curr_layer:
                    if hasattr(curr_layer, 'ttl'):
                        ttls.append(curr_layer.ttl)
                    curr_layer = curr_layer.payload if hasattr(curr_layer, 'payload') else None
                    
            min_ttl = min(ttls) if ttls else 0
            max_ttl = max(ttls) if ttls else 0
            mean_ttl = sum(ttls) / len(ttls) if ttls else 0
            
            resp_data = {
                "response_packet_index": idx,
                "response_timestamp": float(pkt.time),
                "response_len": len(pkt),
                "response_payload_len": len(dns_layer),
                "dns_rcode": dns_layer.rcode,
                "dns_ancount": dns_layer.ancount,
                "dns_nscount": dns_layer.nscount,
                "dns_arcount": dns_layer.arcount,
                "ttl_values": str(ttls),
                "min_ttl": min_ttl,
                "max_ttl": max_ttl,
                "mean_ttl": mean_ttl,
                "is_response_missing": 0
            }
            
            if match_key in queries:
                q_data = queries.pop(match_key)
                q_data.update(resp_data)
                q_data["req_resp_time_diff"] = resp_data["response_timestamp"] - q_data["request_timestamp"]
                q_data["total_transaction_bytes"] = q_data["request_len"] + resp_data["response_len"]
                transactions.append(q_data)
                
    # Any query left in the dictionary didn't get a response
    for missing_query in queries.values():
        missing_query.update({
            "response_packet_index": None,
            "response_timestamp": None,
            "response_len": 0,
            "response_payload_len": 0,
            "dns_rcode": None,
            "dns_ancount": 0,
            "dns_nscount": 0,
            "dns_arcount": 0,
            "ttl_values": "[]",
            "min_ttl": 0,
            "max_ttl": 0,
            "mean_ttl": 0,
            "is_response_missing": 1,
            "req_resp_time_diff": -1,
            "total_transaction_bytes": missing_query["request_len"]
        })
        transactions.append(missing_query)
        
    # Append high-level global metadata parameters per item row
    for tx in transactions:
        tx["source_name"] = "Nitsan"
        tx["source_type"] = "PCAP"
        tx["dataset_id"] = "DNS-Tunnel-Datasets-main"
        tx["source_archive"] = "DNS-Tunnel-Datasets.zip"
        tx["pcap_file"] = os.path.basename(pcap_path)
        tx["pcap_member_path"] = relative_pcap_path
        tx["transaction_id"] = str(uuid.uuid4())
        tx["traffic_label"] = traffic_label
        tx["tool_label"] = tool_label
        tx["project_split"] = project_split
        tx["original_split"] = "none"
        tx["split_group_id"] = os.path.basename(pcap_path)
        tx["label_source"] = "folder_structure"
        tx["is_dns"] = 1
        tx["application_hint"] = "DNS"
        tx["is_doh_traffic"] = 0
        
        # Populate empty structural blocks not targeted heavily by this file context
        for col in SCHEMA_COLUMNS:
            if col not in tx:
                tx[col] = None

    return transactions

def main():
    base_dataset_dir = "./DNS-Tunnel-Datasets"
    output_dir = "./outputs/01_transactions_per_source"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "dns_transactions_nitsan.csv")
    
    if not os.path.exists(base_dataset_dir):
        print(f"Directory {base_dataset_dir} not found. Please verify placement location.")
        return

    all_txs = []
    print("Scanning for PCAP files in DNS-Tunnel-Datasets...")
    
    for root, _, files in os.walk(base_dataset_dir):
        for file in files:
            if file.endswith(('.pcap', '.pcapng')):
                pcap_path = os.path.join(root, file)
                print(f"Processing: {pcap_path}")
                all_txs.extend(process_pcap(pcap_path, base_dataset_dir))

    if all_txs:
        df = pd.DataFrame(all_txs)
        # Force column ordering strictly aligned with schema definition
        df = df[SCHEMA_COLUMNS]
        df.to_csv(output_file, index=False)
        print(f"\nSuccessfully generated {output_file} with {len(df)} transactions.")
    else:
        print("No valid transactions found/processed.")

if __name__ == "__main__":
    main()