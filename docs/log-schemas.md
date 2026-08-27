# Cisco SSE exported log schemas

Captured from representative `.csv.gz` samples on 2026-08-27. The collector must preserve the original row and normalize only fields with clear semantics.

## auditlogs

Fields: `ID`, `Time`, `Email`, `User`, `Type`, `Action`, `Logged in from`, `Before`, `After`.

Primary uses: administrative audit trail, configuration changes, actor attribution, source IP, before/after state, log-export configuration changes.

## dlplogs

Fields: `Timestamp`, `Event Type`, `Unique Event ID`, `Severity`, `Identities`, `Owner`, `Name`, `Application`, `Destination`, `Action`, `Rule Name`, `Data Classification`, `Data Identifier`, `Content Type`, `File Size`, `SHA256 Hash`, `File Label`, `Application Category Name`, `Traffic Direction`, `Private Resource Name`, `Private Resource Group Name`, `Destination Protocol`, `Destination IP`, `Destination Port`, `Organization ID`.

Primary uses: DLP incidents, policy/rule decisions, data classifications, file/hash tracking, destinations, application and private-resource context.

## dnslogs

Fields: `Timestamp`, `Most Granular Identity`, `Identities`, `Internal IP`, `External IP`, `Action`, `Query Type`, `Response Code`, `Domain`, `Categories`, `Most Granular Identity Type`, `Identity Types`, `Blocked Categories`, `Rule ID`, `Destination Countries`, `Organization ID`.

Primary uses: DNS activity, blocked/allowed lookups, category analysis, identity-to-domain relationships, DNS anomaly detection.

## firewalllogs

Fields: `Timestamp`, `Origin IDs`, `Identities`, `Identity Types`, `Direction`, `Protocol`, `Packet Size`, `Source IP`, `Source Port`, `Destination IP`, `Destination Port`, `Data Center`, `Rule ID`, `Action`, `FQDNS`, `Destination List IDs`, `First Packet Timestamp`, `Last Packet Timestamp`, `Packets Sent`, `Packets Received`, `Bytes Sent`, `Bytes Received`, `FW Event ID`, `Destination Country`, `AWS Region`, `App ID`, `Private App ID`, `Private Flow`, `Posture ID`, `CASI Category IDs`, `Traffic Source`, `Content Category IDs`, `Content Category List IDs`, `Organization ID`, `Egress IP`, `Egress`, `Event Correlation ID`, `SGT ID`, `Firewall Block Reason`.

Primary uses: network traffic, policy decisions, byte/packet metrics, application mapping, private flows, posture, egress, countries, and correlation.

## proxylogs

Fields: `Timestamp`, `Policy Identity Label`, `Internal Client IP`, `External Client IP`, `Destination IP`, `Content Type`, `Action`, `URL`, `Referer`, `User Agent`, `Status Code`, `Request Size`, `Response Size`, `Response Body Size`, `SHA256 Hash`, `Categories`, `AV Detections`, `PUAs`, `AMP Disposition`, `AMP Malware Name`, `AMP Score`, `Policy Identity Type`, `Blocked Categories`, `Identities`, `Identity Types`, `Request Method`, `DLP Status`, `Certificate Errors`, `File Name`, `Ruleset ID`, `Rule ID`, `Destination List IDs`, `Isolate Action`, `File Action`, `Warn Status`, `Forwarding Method`, `Producer`, `MSP Organization ID`, `Geo Location Of Blocked Destination Countries`, `Application IDs`, `Host Name`, `Data Center`, `Egress`, `Server Name`, `Time Based Rule`, `Security Overridden`, `Detected Response File Type`, `Warn Categories`, `Organization ID`, `Application Entity Name`, `Application Entity Category`, `Egress IP`, `AI Model Name`, `AI Supply Chain Categories`, `Event Correlation ID`, `Isolate Profile ID`.

Primary uses: web traffic, URL/application analytics, malware/AMP detections, DLP status, certificate errors, isolation/warn actions, user-agent analytics, application and AI supply-chain analytics.

## rceventlogs

Fields: `Timestamp`, `Organization ID`, `MSP Organization ID`, `Origin IDs`, `Origin Type`, `Event ID`, `Event Label`, `Event Type`, `Event Level`, `Event Duration (s)`, `Event User ID`, `Event Client ID`, `Connector Group ID`, `Region`, `Agent Config Status`, `Agent Tunnel Status`, `Agent Controller Status`, `Agent Config In Sync`, `Agent Certificate Status`, `Agent Certificate Expire Date`, `Agent Base OS Version`, `Agent Software Version`, `Log Type`.

Primary uses: connector health, tunnel/controller/config state, certificate state, software versions, connector-group health.

## ztnaflowlogs

Fields: `Timestamp`, `Identity Email`, `Identity Labels`, `Identity Type Labels`, `Organization ID`, `MSP Organization ID`, `Host Name`, `Transaction ID`, `Private Resource ID`, `Private Resource Group ID`, `App Connector ID`, `App Connector Group ID`, `Ruleset ID`, `Rule ID`, `Connection Status`, `Connection Failure Reason`, `Headend Type`, `Event Type`, `Rx Bytes`, `Tx Bytes`, `Egress IP`, `Egress Port`, `NT Group ID`, `ZTA Source Port`, `Enforced By`, `FTD Enforcement ID`, `FTD Enforcement Name`.

Primary uses: ZTNA/private application access, connector selection, connection failures, transaction correlation, byte volume, rulesets and enforcement.

## Design note

Keep `raw_event` JSON for every event. Do not discard Cisco-specific fields while the schema is still being learned. The canonical model should provide common dimensions for cross-source analytics while source-specific columns remain available for detailed investigation.
