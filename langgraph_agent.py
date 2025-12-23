# langgraph_agent.py
import os
import logging
import configparser
import datetime
import time
import subprocess
import sys
from typing import TypedDict, Annotated, List
import operator

# --- Library Import Checks ---
try:
    import pandas as pd
    import paramiko
    from scp import SCPClient
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS
    from langchain_core.messages import BaseMessage, HumanMessage
    from langchain_community.chat_models import ChatOllama
    from langgraph.graph import StateGraph, END
except ImportError as e:
    print(f"Error: A required library is not installed. Please run 'pip install paramiko scp scapy pandas langchain langgraph langchain_community ollama' in your terminal. Details: {e}")
    sys.exit(1)


# --- Agent State ---
class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    config: dict
    timestamp: str
    local_pcap_path: str
    analysis_results: dict
    decision: str

# --- Logging and Configuration ---
LOG_FILE = 'agent.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

def load_config(state):
    config_file = 'config.ini.txt'
    parser = configparser.ConfigParser()
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file {config_file} not found.")
    parser.read(config_file)
    config_dict = {s: dict(parser.items(s)) for s in parser.sections()}
    return {"config": config_dict}

def create_ssh_client(hostname, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        logging.info(f"Connecting to {username}@{hostname}:{port}...")
        client.connect(hostname, port=port, username=username, password=password, timeout=10)
        logging.info("Successfully connected.")
        return client
    except Exception as e:
        logging.error(f"Could not connect to SSH server: {e}")
        raise

# --- Graph Nodes ---
def capture_packets(state: AgentState) -> dict:
    logging.info("--- NODE: Capture Packets ---")
    config = state['config']
    ssh_config = config['ssh_server']
    capture_config = config['capture']
    local_pcap_dir = capture_config.get('local_pcap_dir', './captures')
    if not os.path.exists(local_pcap_dir):
        os.makedirs(local_pcap_dir)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    local_pcap_filename = f"capture_{timestamp}.pcap"
    local_pcap_full_path = os.path.join(local_pcap_dir, local_pcap_filename)
    remote_path = capture_config['remote_pcap_path']

    ssh_client = None
    try:
        ssh_client = create_ssh_client(
            ssh_config['hostname'], int(ssh_config['port']),
            ssh_config['username'], ssh_config['password']
        )
        command = f"sudo /usr/bin/tcpdump -i {capture_config['interface']} -c {capture_config['packet_count']} -w {remote_path}"
        logging.info(f"Executing remote command: {command}")
        stdin, stdout, stderr = ssh_client.exec_command(command, get_pty=True)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            raise RuntimeError(f"tcpdump failed. Stderr: {stderr.read().decode()}")

        with SCPClient(ssh_client.get_transport()) as scp:
            logging.info(f"Downloading {remote_path} to {local_pcap_full_path}...")
            scp.get(remote_path, local_pcap_full_path)
        logging.info("File downloaded successfully.")

        ssh_client.exec_command(f"rm {remote_path}")
        logging.info(f"Deleted remote file {remote_path}.")
    finally:
        if ssh_client:
            ssh_client.close()

    return {"timestamp": timestamp, "local_pcap_path": local_pcap_full_path}

def initial_analysis(state: AgentState) -> dict:
    logging.info("--- NODE: Initial Analysis ---")
    pcap_path = state['local_pcap_path']
    config = state['config']
    capture_config = config['capture']
    timestamp = state['timestamp']
    results = {}

    try:
        packets = rdpcap(pcap_path)
        source_ips = {}
        for packet in packets:
            if IP in packet:
                source_ips[packet[IP].src] = source_ips.get(packet[IP].src, 0) + 1
        results['scapy_analysis'] = {
            "total_packets": len(packets),
            "top_5_source_ips": sorted(source_ips.items(), key=lambda item: item[1], reverse=True)[:5]
        }
        logging.info(f"Scapy Analysis Results: {results['scapy_analysis']}")
    except Exception as e:
        logging.error(f"Scapy analysis failed: {e}")
        results['scapy_analysis'] = {"error": str(e)}

    local_pcap_dir = os.path.dirname(pcap_path)
    anomaly_csv_path = os.path.join(local_pcap_dir, f"anomaly_data_{timestamp}.csv")
    anomaly_script_path = capture_config.get('anomaly_detector_script_path', 'anomaly_detector.py')
    contamination = capture_config.get('ml_contamination', '0.05')
    
    command = [sys.executable, anomaly_script_path, pcap_path, anomaly_csv_path, f"--contamination={contamination}"]
    
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        df_anomalies = pd.read_csv(anomaly_csv_path)
        num_anomalies = int(df_anomalies['is_anomaly'].sum())
        anomalous_packets = df_anomalies[df_anomalies['is_anomaly'] == 1].to_dict('records')
        results['ml_analysis'] = {
            "anomalies_found": num_anomalies,
            "anomalous_packets_sample": anomalous_packets[:3]
        }
        logging.info(f"ML Analysis Results: {results['ml_analysis']}")
    except Exception as e:
        logging.error(f"ML anomaly detection failed: {e}")
        results['ml_analysis'] = {"error": str(e)}

    return {"analysis_results": results}

def reason_and_decide(state: AgentState) -> dict:
    logging.info("--- NODE: Reason and Decide ---")
    analysis = state['analysis_results']
    prompt = f"""
You are a senior network security analyst AI. Your job is to analyze network traffic reports and decide on the next course of action.
You have been presented with the following summary from a recent packet capture:

### Scapy Analysis ###
{analysis.get('scapy_analysis', 'Not available')}

### Isolation Forest Anomaly Detection ###
{analysis.get('ml_analysis', 'Not available')}

### Analysis & Next Step ###
Based on this data, please provide a brief analysis of the situation. Conclude your analysis with your decision on the next step.
Your decision MUST be one of the following three options, and nothing else:
- **DECISION: NORMAL** (If the traffic looks benign and no further action is needed).
- **DECISION: DEEP_SCAN_REQUIRED** (If the findings are suspicious and warrant a more detailed investigation with specialized tools).
- **DECISION: CRITICAL_ALERT** (If the findings strongly indicate a malicious attack in progress).
"""
    
    llm = ChatOllama(model="llama3", temperature=1)
    response = llm.invoke(prompt)
    logging.info(f"LLM Analyst Report:\n{response.content}")

    decision = "NORMAL" # Default
    if "DEEP_SCAN_REQUIRED" in response.content.upper():
        decision = "DEEP_SCAN_REQUIRED"
    elif "CRITICAL_ALERT" in response.content.upper():
        decision = "CRITICAL_ALERT"
        
    logging.info(f"Decision made by LLM: {decision}")
    
    return {
        "messages": [HumanMessage(content=response.content)],
        "decision": decision
    }

def perform_deep_scan(state: AgentState) -> dict:
    logging.info("--- NODE: Perform Deep Scan ---")
    config = state['config']
    capture_config = config['capture']
    pcap_path = state['local_pcap_path']
    timestamp = state['timestamp']
    script_path = capture_config.get('deep_scan_script_path')
    output_dir = os.path.dirname(pcap_path)
    
    if not script_path or not os.path.exists(script_path):
        logging.warning(f"Deep scan script not found at {script_path}. Skipping.")
        return {"messages": [HumanMessage(content="Deep scan was required but script was not found.")]}
        
    report_path = os.path.join(output_dir, f"anomaly_report_shell_{timestamp}.txt")
    
    try:
        process = subprocess.run(
            f"bash {script_path} {pcap_path}", shell=True, check=True, capture_output=True, text=True
        )
        with open(report_path, 'w') as f:
            f.write(process.stdout)
        logging.info(f"Deep scan successful. Report at {report_path}")
        deep_scan_summary = f"Deep scan completed. Key findings:\n{process.stdout[:1000]}"
        return {"messages": [HumanMessage(content=deep_scan_summary)]}
    except Exception as e:
        logging.error(f"Deep scan shell script failed: {e}")
        return {"messages": [HumanMessage(content=f"Deep scan failed to execute: {e}")]}

def generate_final_report(state: AgentState) -> dict:
    logging.info("--- NODE: Final Report ---")
    report_context = [
        HumanMessage(content="You are a security reporting AI. Synthesize all the information provided into a single, final report for this cycle. Start with the final verdict (Normal, Suspicious, or Critical)."),
    ] + state['messages']

    llm = ChatOllama(model="llama3", temperature=1)
    final_report = llm.invoke(report_context)
    logging.info(f"\n--- CYCLE FINAL REPORT ---\n{final_report.content}\n--------------------------\n")
    return {"messages": [final_report]}

def route_after_decision(state: AgentState) -> str:
    logging.info("--- ROUTING ---")
    decision = state['decision']
    if decision == "DEEP_SCAN_REQUIRED":
        return "perform_deep_scan"
    else:
        return "generate_final_report"

def build_graph():
    workflow = StateGraph(AgentState)
    workflow.add_node("load_config", load_config)
    workflow.add_node("capture_packets", capture_packets)
    workflow.add_node("initial_analysis", initial_analysis)
    workflow.add_node("reason_and_decide", reason_and_decide)
    workflow.add_node("perform_deep_scan", perform_deep_scan)
    workflow.add_node("generate_final_report", generate_final_report)
    workflow.set_entry_point("load_config")
    workflow.add_edge("load_config", "capture_packets")
    workflow.add_edge("capture_packets", "initial_analysis")
    workflow.add_edge("initial_analysis", "reason_and_decide")
    workflow.add_conditional_edges(
        "reason_and_decide", route_after_decision,
        {"perform_deep_scan": "perform_deep_scan", "generate_final_report": "generate_final_report"}
    )
    workflow.add_edge("perform_deep_scan", "generate_final_report")
    workflow.add_edge("generate_final_report", END)
    return workflow.compile()

def main():
    app = build_graph()
    try:
        parser = configparser.ConfigParser()
        parser.read('config.ini.txt')
        interval_seconds = int(parser.get('capture', 'interval_seconds', fallback=60))
    except Exception as e:
        logging.warning(f"Could not read interval from config. Defaulting to 60s. Error: {e}")
        interval_seconds = 60

    while True:
        try:
            logging.info("--- Starting new agent cycle ---")
            initial_state = {"messages": []}
            # Using invoke to run the full graph to completion for one cycle
            app.invoke(initial_state)
            logging.info(f"--- Agent cycle finished. Waiting for {interval_seconds} seconds. ---")
            time.sleep(interval_seconds)
        except KeyboardInterrupt:
            logging.info("Agent stopped by user.")
            break
        except FileNotFoundError as e:
            logging.critical(f"A required file was not found: {e}. The agent cannot continue. Please check your config.ini.txt and script paths.")
            break
        except Exception as e:
            logging.error(f"An error occurred during the agent cycle: {e}", exc_info=True)
            logging.info(f"Retrying after {interval_seconds} seconds.")
            time.sleep(interval_seconds)

if __name__ == "__main__":
    main()