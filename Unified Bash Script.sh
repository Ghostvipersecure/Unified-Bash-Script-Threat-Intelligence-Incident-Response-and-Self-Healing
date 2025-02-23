#!/bin/bash

# Splunk HEC settings
SPLUNK_HEC_URL="https://your-splunk-instance:8088"
SPLUNK_HEC_TOKEN="your-splunk-hec-token"

# Threat Intelligence source (e.g., MISP, OpenDXL, or commercial feeds)
INTELLIGENCE_FEED_URL="https://your-threat-feed-source"
FEED_API_KEY="your-api-key"

# Splunk URL for alerting and case creation
SPLUNK_URL="https://your-splunk-instance:8089"
SPLUNK_USER="your-username"
SPLUNK_PASSWORD="your-password"

# Self-healing interval (in minutes)
HEALING_INTERVAL=1440  # 1 day (run once per day for self-healing updates)

# Function to block IP in firewall (remediation)
block_ip() {
    local IP=$1
    # Block IP in firewall (example for iptables)
    iptables -A INPUT -s "$IP" -j DROP
    echo "Blocked IP: $IP"

    # Send log to Splunk for remediation action
    curl -k -X POST "$SPLUNK_HEC_URL/services/collector/event" \
        -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
        -d '{"event":"IP '$IP' blocked in firewall","sourcetype":"incident_response","index":"security"}'

    # Create an incident in Splunk (Optional: For ITSI)
    curl -k -X POST "$SPLUNK_URL/services/itsi/incident/create" \
        -u "$SPLUNK_USER:$SPLUNK_PASSWORD" \
        -d "title=Suspicious IP Blocked: $IP&severity=high&description=Automated incident response triggered."
}

# Polling the threat feed to gather IoCs and continuously monitor for threats
while true; do
    # Fetch Threat Intelligence feed
    echo "Fetching Threat Intelligence Feed..."
    THREAT_FEED=$(curl -k -H "Authorization: Bearer $FEED_API_KEY" "$INTELLIGENCE_FEED_URL")

    # Extract IP addresses (or any other IoC) from the threat feed
    IP_LIST=$(echo "$THREAT_FEED" | jq -r '.data.indicators[].value')  # Example for IP addresses

    # Loop through IPs from the feed
    for IP in $IP_LIST; do
        echo "Checking for correlation with internal logs for IP: $IP"

        # Search for logs with this IP (internal logs)
        LOGS=$(curl -k -u "$SPLUNK_USER:$SPLUNK_PASSWORD" \
            "$SPLUNK_URL/services/search/jobs" \
            -d "search=search index=_internal \"src_ip=$IP\" earliest=-1h@h | stats count by src_ip")

        if [[ ! -z "$LOGS" ]]; then
            # Trigger alert in Splunk if correlation is found
            ALERT_MSG="Suspicious activity detected: IP $IP correlated with internal logs"
            echo "$ALERT_MSG" | curl -k -X POST "$SPLUNK_HEC_URL/services/collector/event" \
                -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
                -d '{"event":"'$ALERT_MSG'","sourcetype":"alert","index":"security"}'

            # Trigger automated incident response by blocking the IP
            block_ip "$IP"
        fi
    done

    # Self-healing process (update threat sources and update firewall)
    if (( $(date +%s) % (HEALING_INTERVAL * 60) == 0 )); then
        echo "Initiating self-healing process..."
        # Fetch new threat intelligence for automatic update of firewall or blacklist
        curl -k -H "Authorization: Bearer $FEED_API_KEY" "$INTELLIGENCE_FEED_URL" > /etc/splunk/new_iocs.json

        # Extract new IPs and update firewall rules
        NEW_IPS=$(jq -r '.data.indicators[].value' /etc/splunk/new_iocs.json)
        for IP in $NEW_IPS; do
            iptables -A INPUT -s "$IP" -j DROP  # Add new IPs to the blocklist
        done

        # Send update event to Splunk
        curl -k -X POST "$SPLUNK_HEC_URL/services/collector/event" \
            -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
            -d '{"event":"Firewall rules updated with new IoCs","sourcetype":"self_healing","index":"security"}'
    fi

    # Sleep before next iteration
    sleep 5m  # 5-minute polling interval for new threat data
done
