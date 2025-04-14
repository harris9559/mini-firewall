#!/usr/bin/env python3

import streamlit as st
import yaml
import pandas as pd
import matplotlib.pyplot as plt
from firewall import MiniFirewall
import time
import os

# Dashboard configuration
st.set_page_config(
    page_title="Mini Firewall Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Initialize firewall
firewall = MiniFirewall()

# Sidebar controls
st.sidebar.title("Firewall Controls")

def load_rules():
    """Load rules from YAML file"""
    try:
        with open('firewall_rules.yaml', 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return firewall.get_default_rules()

def save_rules(rules):
    """Save rules to YAML file"""
    with open('firewall_rules.yaml', 'w') as f:
        yaml.dump(rules, f)

def main():
    # Load current rules
    rules = load_rules()
    
    # Status indicator
    status = st.sidebar.radio("Firewall Status", ["Stopped", "Running"], index=0)
    if status == "Running":
        st.sidebar.warning("Note: Running the firewall requires sudo privileges")
        if st.sidebar.button("Start Firewall (Requires Terminal)"):
            st.sidebar.info("Please run 'sudo python firewall.py' in terminal")
    
    # Rule management
    st.sidebar.subheader("IP Management")
    ip_to_add = st.sidebar.text_input("Add IP to block")
    if st.sidebar.button("Add IP"):
        if ip_to_add:
            if ip_to_add not in rules['blocked_ips']:
                rules['blocked_ips'].append(ip_to_add)
                save_rules(rules)
                st.sidebar.success(f"Added {ip_to_add} to blocked IPs")
            else:
                st.sidebar.warning(f"{ip_to_add} is already blocked")
    
    ip_to_remove = st.sidebar.selectbox("Remove IP from block list", rules['blocked_ips'])
    if st.sidebar.button("Remove IP"):
        rules['blocked_ips'].remove(ip_to_remove)
        save_rules(rules)
        st.sidebar.success(f"Removed {ip_to_remove} from blocked IPs")
    
    st.sidebar.subheader("Port Management")
    port_to_add = st.sidebar.number_input("Add port to block", min_value=1, max_value=65535, step=1)
    if st.sidebar.button("Add Port"):
        if port_to_add not in rules['blocked_ports']:
            rules['blocked_ports'].append(int(port_to_add))
            save_rules(rules)
            st.sidebar.success(f"Added port {port_to_add} to blocked ports")
        else:
            st.sidebar.warning(f"Port {port_to_add} is already blocked")
    
    port_to_remove = st.sidebar.selectbox("Remove port from block list", rules['blocked_ports'])
    if st.sidebar.button("Remove Port"):
        rules['blocked_ports'].remove(port_to_remove)
        save_rules(rules)
        st.sidebar.success(f"Removed port {port_to_remove} from blocked ports")
    
    # Main dashboard
    st.title("Mini Firewall Dashboard")
    
    # Display current rules
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Blocked IP Addresses")
        st.table(pd.DataFrame(rules['blocked_ips'], columns=["IP Addresses"]))
    
    with col2:
        st.subheader("Blocked Ports")
        st.table(pd.DataFrame(rules['blocked_ports'], columns=["Ports"]))
    
    # Protocol settings
    st.subheader("Allowed Protocols")
    protocols = ["TCP", "UDP", "ICMP"]
    cols = st.columns(len(protocols))
    
    protocol_states = {}
    for i, protocol in enumerate(protocols):
        with cols[i]:
            state = st.checkbox(protocol, protocol in rules['allowed_protocols'])
            protocol_states[protocol] = state
    
    if st.button("Update Protocols"):
        rules['allowed_protocols'] = [p for p, s in protocol_states.items() if s]
        save_rules(rules)
        st.success("Protocol settings updated!")
    
    # Log visualization
    st.subheader("Firewall Log Analysis")
    
    if os.path.exists('firewall.log'):
        log_data = []
        with open('firewall.log', 'r') as f:
            for line in f:
                parts = line.strip().split(' - ')
                if len(parts) >= 2:
                    log_data.append({
                        'timestamp': parts[0],
                        'message': parts[1]
                    })
        
        if log_data:
            log_df = pd.DataFrame(log_data)
            
            # Show raw log
            if st.checkbox("Show Raw Log Data"):
                st.dataframe(log_df)
            
            # Basic statistics
            st.write("### Log Statistics")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Log Entries", len(log_df))
            
            with col2:
                actions = log_df['message'].str.extract(r'^(Allowed|Blocked)')[0].value_counts()
                st.dataframe(actions)
            
            with col3:
                protocols = log_df['message'].str.extract(r'protocol\': \'(\w+)')[0].value_counts()
                st.dataframe(protocols)
            
            # Time series chart
            st.write("### Activity Over Time")
            log_df['datetime'] = pd.to_datetime(log_df['timestamp'])
            time_series = log_df.set_index('datetime').resample('5T').size()
            st.line_chart(time_series)
        else:
            st.warning("Log file exists but contains no valid data")
    else:
        st.warning("No log file found. Firewall must be run to generate logs.")

if __name__ == "__main__":
    main()