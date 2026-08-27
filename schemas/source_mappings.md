# Cisco SSE source mappings

Derived from representative exported CSV samples. Raw production samples are intentionally not stored in this repository.

## auditlogs

`ID, Time, Email, User, Type, Action, Logged in from, Before, After`

Primary uses: administrative activity, configuration changes, audit trail, change attribution.

## dlplogs

`Timestamp, Event Type, Unique Event ID, Severity, Identities, Owner, Name, Application, Destination, Action, Rule Name, Data Classification, Data Identifier, Content Type, File Size, SHA256 Hash, File Label, Application Category Name, Traffic Direction, Private Resource Name, Private Resource Group Name, Destination Protocol, Destination IP, Destination Port, Organization ID`

Primary uses: DLP incidents, sensitive-data movement, policy/rule effectiveness, file/entity investigation.

## dnslogs

`Timestamp, Most Granular Identity, Identities, Internal IP, External IP, Action, Query Type, Response Code, Domain, Categories, Most Granular Identity Type, Identity Types, Blocked Categories, Rule ID, Destination Countries, Organization ID`

Primary uses: DNS activity, blocked domains, category analytics, identity/domain correlation, suspicious-domain detections.

## firewalllogs

`Timestamp, Origin IDs, Identities, Identity Types, Direction, Protocol, Packet Size, Source IP, Source Port, Destination IP, Destination Port, Data Center, Rule ID, Action, FQDNS, Destination List IDs, First Packet Timestamp, Last Packet Timestamp, Packets Sent, Packets Received, Bytes Sent, Bytes Received, FW Event ID, Destination Country, AWS Region, App ID, Private App ID, Private Flow, Posture ID, CASI Category IDs, Traffic Source, Content Category IDs, Content Category List IDs, Organization ID, Egress IP, Egress, Event Correlation ID, SGT ID, Firewall Block Reason`

Primary uses: network traffic, connection policy, byte/packet analytics, application analytics, country/egress analytics, correlation.

## proxylogs

`Timestamp, Policy Identity Label, Internal Client IP, External Client IP, Destination IP, Content Type, Action, URL, Referer, User Agent, Status Code, Request Size, Response Size, Response Body Size, SHA256 Hash, Categories, AV Detections, PUAs, AMP Disposition, AMP Malware Name, AMP Score, Policy Identity Type, Blocked Categories, Identities, Identity Types, Request Method, DLP Status, Certificate Errors, File Name, Ruleset ID, Rule ID, Destination List IDs, Isolate Action, File Action, Warn Status, Forwarding Method, Producer, MSP Organization ID, Geo Location Of Blocked Destination Countries, Application IDs, Host Name, Data Center, Egress, Server Name, Time Based Rule, Security Overridden, Detected Response File Type, Warn Categories, Organization ID, Application Entity Name, Application Entity Category, Egress IP, AI Model Name, AI Supply Chain Categories, Event Correlation ID, Isolate Profile ID`

Primary uses: web traffic, malware/AMP, URL/category analytics, DLP correlation, certificate errors, isolation/warnings, AI/SaaS analytics.

## rceventlogs

`Timestamp, Organization ID, MSP Organization ID, Origin IDs, Origin Type, Event ID, Event Label, Event Type, Event Level, Event Duration (s), Event User ID, Event Client ID, Connector Group ID, Region, Agent Config Status, Agent Tunnel Status, Agent Controller Status, Agent Config In Sync, Agent Certificate Status, Agent Certificate Expire Date, Agent Base OS Version, Agent Software Version, Log Type`

Primary uses: Remote Connector health, tunnel/config/controller state, certificate lifecycle, connector inventory and health scoring.

## ztnaflowlogs

`Timestamp, Identity Email, Identity Labels, Identity Type Labels, Organization ID, MSP Organization ID, Host Name, Transaction ID, Private Resource ID, Private Resource Group ID, App Connector ID, App Connector Group ID, Ruleset ID, Rule ID, Connection Status, Connection Failure Reason, Headend Type, Event Type, Rx Bytes, Tx Bytes, Egress IP, Egress Port, NT Group ID, ZTA Source Port, Enforced By, FTD Enforcement ID, FTD Enforcement Name`

Primary uses: private application access, connection success/failure, connector performance, user/resource analytics, ZTNA investigation.

## Canonical dimensions

The first normalized model should preserve source-specific fields while extracting common dimensions:

- event_time
- source_type
- organization_id
- user_identity
- identity_type
- hostname/device
- source_ip
- destination_ip
- destination_domain/url
- destination_port
- protocol
- action
- policy_id/rule_id/ruleset_id
- application
- category
- country
- bytes_sent/bytes_received
- packets_sent/packets_received
- event_correlation_id
- severity
- threat/malware indicators
- raw_event JSON

Source-specific fields remain available in typed source tables or a raw JSON column so analytics does not discard telemetry.