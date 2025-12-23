import paramiko
from scp import SCPClient
import time
import datetime
import os
import logging
import configparser
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS

# --- Configuration ---
CONFIG_FILE = 'config.ini.txt'
LOG_FILE = 'agent.log'

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# --- Helper Functions ---
def load_config():
    parser = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        logging.error(f"Configuration file {CONFIG_FILE} not found.")
        raise FileNotFoundError(f"Configuration file {CONFIG_FILE} not found.")
    parser.read(CONFIG_FILE)
    return parser

def create_ssh_client(hostname, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        logging.info(f"Connecting to {username}@{hostname}:{port}...")
        client.connect(hostname, port=port, username=username, password=password, timeout=10)
        logging.info("Successfully connected.")
        return client
    except paramiko.AuthenticationException:
        logging.error("Authentication failed. Please check credentials.")
        raise
    except Exception as e:
        logging.error(f"Could not connect to SSH server: {e}")
        raise

def run_remote_tcpdump(client, interface, count, remote_file_path):
    command = f"sudo /usr/bin/tcpdump -i {interface} -c {count} -w {remote_file_path}"
    logging.info(f"Executing remote command: {command}")
    stdin, stdout, stderr = client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status == 0:
        logging.info(f"tcpdump completed successfully on remote server. Output stored in {remote_file_path}")
    else:
        error_message = stderr.read().decode().strip()
        logging.error(f"tcpdump failed: {error_message}")
        raise RuntimeError(f"tcpdump failed: {error_message}")

def download_file_sftp(client, remote_path, local_path):
    try:
        with SCPClient(client.get_transport()) as scp:
            logging.info(f"Downloading {remote_path} to {local_path}...")
            scp.get(remote_path, local_path)
            logging.info("File downloaded successfully.")
    except Exception as e:
        logging.error(f"Failed to download file {remote_path}: {e}")
        raise

def delete_remote_file(client, remote_path):
    command = f"rm -f {remote_path}"
    logging.info(f"Deleting remote file: {remote_path}")
    stdin, stdout, stderr = client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status == 0:
        logging.info(f"Successfully deleted remote file {remote_path}.")
    else:
        logging.warning(f"Could not delete remote file {remote_path}. Error: {stderr.read().decode().strip()}")

def analyze_pcap(pcap_file_path):
    if not os.path.exists(pcap_file_path):
        logging.warning(f"PCAP file {pcap_file_path} not found for analysis.")
        return

    logging.info(f"Analyzing {pcap_file_path}...")
    try:
        packets = rdpcap(pcap_file_path)
        logging.info(f"Total packets captured: {len(packets)}")

        ip_packets = 0
        tcp_packets = 0
        udp_packets = 0
        icmp_packets = 0
        dns_queries = 0
        source_ips = {}

        for packet in packets:
            if IP in packet:
                ip_packets += 1
                src_ip = packet[IP].src
                source_ips[src_ip] = source_ips.get(src_ip, 0) + 1
                if TCP in packet:
                    tcp_packets += 1
                    if packet.haslayer(DNS) and packet[DNS].qr == 0:
                        dns_queries += 1
                elif UDP in packet:
                    udp_packets += 1
                    if packet.haslayer(DNS) and packet[DNS].qr == 0:
                        dns_queries += 1
                elif ICMP in packet:
                    icmp_packets += 1

        logging.info(f"  IP Packets: {ip_packets}")
        logging.info(f"  TCP Packets: {tcp_packets}")
        logging.info(f"  UDP Packets: {udp_packets}")
        logging.info(f"  ICMP Packets: {icmp_packets}")
        logging.info(f"  DNS Queries: {dns_queries}")

        if source_ips:
            logging.info("  Top 5 Source IPs by packet count:")
            sorted_ips = sorted(source_ips.items(), key=lambda item: item[1], reverse=True)
            for ip, count in sorted_ips[:5]:
                logging.info(f"    {ip}: {count} packets")

    except Exception as e:
        logging.error(f"Error analyzing PCAP file {pcap_file_path}: {e}")

# --- Main Agent Logic ---
def main():
    try:
        config = load_config()
        ssh_config = config['ssh_server']
        capture_config = config['capture']
        local_pcap_dir = capture_config.get('local_pcap_dir', './captures')

        if not os.path.exists(local_pcap_dir):
            os.makedirs(local_pcap_dir)
            logging.info(f"Created local capture directory: {local_pcap_dir}")

    except Exception as e:
        logging.critical(f"Failed to initialize agent: {e}")
        return

    while True:
        ssh_client = None
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            local_pcap_filename = f"capture_{timestamp}.pcap"
            local_pcap_full_path = os.path.join(local_pcap_dir, local_pcap_filename)

            logging.info("--- Starting new capture cycle ---")

            ssh_client = create_ssh_client(
                ssh_config['hostname'],
                int(ssh_config['port']),
                ssh_config['username'],
                ssh_config['password']
            )

            run_remote_tcpdump(
                ssh_client,
                capture_config['interface'],
                capture_config['packet_count'],
                capture_config['remote_pcap_path']
            )

            download_file_sftp(
                ssh_client,
                capture_config['remote_pcap_path'],
                local_pcap_full_path
            )

            delete_remote_file(ssh_client, capture_config['remote_pcap_path'])

            analyze_pcap(local_pcap_full_path)

            # Run anomaly detection
            anomaly_report_path = os.path.join(
                local_pcap_dir,
                f"anomaly_report_{timestamp}.txt"
            )
            os.system(f"/home/inv-6/packet_monitorning/captures/deep_anomaly_scan.sh {local_pcap_full_path} > {anomaly_report_path}")

            #os.system(f"/home/inv-6/packet_monitorning/captures/deep_anomaly_scan.sh > {anomaly_report_path}")
            logging.info(f"Anomaly report written to: {anomaly_report_path}")

        except FileNotFoundError:
            logging.critical("Configuration file missing. Agent cannot run. Exiting.")
            break
        except paramiko.AuthenticationException:
            logging.error("SSH Authentication failed. Check credentials in config. Agent will retry later.")
        except RuntimeError as e:
            logging.error(f"Runtime error during capture cycle: {e}. Agent will retry later.")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        finally:
            if ssh_client:
                ssh_client.close()
                logging.info("SSH connection closed.")
            logging.info(f"--- Capture cycle finished. Waiting for {capture_config['interval_seconds']} seconds. ---")
            try:
                time.sleep(int(capture_config['interval_seconds']))
            except KeyboardInterrupt:
                logging.info("Agent stopped by user.")
                break
            except Exception as e:
                logging.error(f"Error in sleep interval configuration: {e}. Defaulting to 300 seconds.")
                time.sleep(300)

if __name__ == "__main__":
    main()
