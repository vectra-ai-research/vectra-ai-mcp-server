# Network Schemas

Schemas for network-based metadata produced by Vectra sensors.

Notation:

- Nested struct fields use dotted paths, e.g. `id.orig_h`.
- Arrays are marked with `[]` on the parent segment, e.g. `resources[].arn`.
- The `Type` column shows the underlying scalar type; when a `usage` hint is present in the schema it is appended in parentheses, e.g. `string (ip_address)`.

## Metadata Types

- [`beacon`](#beacon)
- [`dcerpctxn`](#dcerpctxn)
- [`dhcp`](#dhcp)
- [`dnsrecordinfo`](#dnsrecordinfo)
- [`httpsessioninfo`](#httpsessioninfo)
- [`isession`](#isession)
- [`kerberostxn`](#kerberostxn)
- [`ldap`](#ldap)
- [`ntlm`](#ntlm)
- [`radius`](#radius)
- [`rdp`](#rdp)
- [`smbfilestxn`](#smbfilestxn)
- [`smbmappingtxn`](#smbmappingtxn)
- [`smtp`](#smtp)
- [`ssh`](#ssh)
- [`ssl`](#ssl)
- [`suricata`](#suricata)
- [`x509`](#x509)

## beacon

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `resp_domains[]` | `string` | The domain or list of domains for the resp relative to the Uid |
| `beacon_uid` | `string` | Unique ID for the beacon spanning multiple events |
| `beacon_type` | `string` | Characterization of the beacon type being reported |
| `duration` | `decimal(20,0) (quantity)` | Total duration of the BeaconUid, in milliseconds |
| `first_event_time` | `timestamp` | Timestamp for first session of the BeaconUid |
| `ja3` | `string` | Hash of server cert |
| `last_event_time` | `timestamp` | Timestamp for last session of the BeaconUid |
| `local_orig` | `boolean` | True if the orig is in the local network |
| `local_resp` | `boolean` | True if the resp is in the local network |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin host local unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `orig_ip_bytes` | `decimal(20,0) (quantity)` | Total orig bytes over the BeaconUid |
| `orig_sluid` | `string` | Origin Sluid |
| `orig_huid` | `string` | Origin unique ID |
| `proto` | `smallint` | The transport layer protocol of the connection |
| `proto_name` | `string` | The name of the transport layer |
| `resp_ip_bytes` | `decimal(20,0) (quantity)` | Total resp bytes over the BeaconUid |
| `service` | `string` | An identification of an application protocol being sent over the connection |
| `session_count` | `decimal(20,0) (quantity)` | Number of SF conns in BeaconUid |
| `timestamp` | `timestamp` | Timestamp for last session of the reported beacon (us) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor of the first event |

## dcerpctxn

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin unique ID |
| `resp_huid` | `string` | Response unique ID |
| `username` | `string` | The username making the RPC call |
| `hostname` | `string` | The hostname of the server |
| `domain` | `string` | The domain of the server |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `rtt` | `decimal(20,0) (quantity)` | Round trip time from the request to the response. If either the request or response wasn’t seen, this will be 0 |
| `endpoint` | `string` | Endpoint name looked up from the uuid |
| `operation` | `string` | Operation seen in the call |

## dhcp

_Latest version: `v1.1.0` (available: `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `dns_server_ips[]` | `string (ip_address)` | IP addresses of the DNS servers suggested during the lease |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `mac` | `string` | Mac address in the format “MM:MM:MM:SS:SS:SS” |
| `assigned_ip` | `string (ip_address)` | IP address assigned by the server |
| `trans_id` | `bigint` | Transaction ID |
| `lease_time` | `bigint (quantity)` | IP address lease interval |
| `server_addr` | `string (ip_address)` | IP address of the server involved in actually handing out the lease |
| `orig_hostname` | `string` | Origin hostname |

## dnsrecordinfo

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `answers[]` | `string` | The set of resource descriptions in the query answer |
| `answers_error` | `string` | Contains an error description for the inability to parse the query answer |
| `auth[]` | `string` | Authoritative responses for the query |
| `ttls[]` | `int (quantity)` | The caching intervals of the associated RRs described by the answers field |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `proto` | `tinyint` | The transport layer protocol of the connection |
| `trans_id` | `smallint` | A 16-bit identifier assigned by the program that generated the DNS query, also used in responses to match up replies to outstanding queries |
| `query` | `string` | The domain name that is the subject of the DNS query |
| `qclass` | `smallint` | The QCLASS value specifying the class of the query |
| `qclass_name` | `string` | A descriptive name for the class of the query |
| `qtype` | `smallint` | A QTYPE value specifying the type of the query |
| `qtype_name` | `string` | A descriptive name for the type of the query |
| `rcode` | `smallint` | The response code value in DNS response messages |
| `rcode_name` | `string` | A descriptive name for the response code value |
| `rejected` | `boolean` | If true The DNS query was rejected by the server |
| `total_answers` | `int (quantity)` | The total number of resource records in a reply message's answer section |
| `total_replies` | `int (quantity)` | The total number of resource records in a reply message's answer, authority, and additional sections |
| `saw_query` | `boolean` | Whether the full DNS query has been seen |
| `saw_reply` | `boolean` | Whether the full DNS reply has been seen |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin host unique ID |
| `resp_huid` | `string` | Response host unique ID |
| `aa` | `boolean` | The Authoritative Answer. If true specifies that the responding name server is an authority for the domain name in the question section |
| `tc` | `boolean` | The Truncation indicator. If true specifies that the message was truncated |
| `rd` | `boolean` | The Recursion Desired in a request message. If true indicates that the client wants recursive service for this query |
| `ra` | `boolean` | The Recursion Available in a response message. If True indicates that the name server supports recursive queries. |

## httpsessioninfo

_Latest version: `v1.5.0` (available: `v1.5.0`, `v1.4.0`, `v1.3.0`, `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `proxied[]` | `string` | All of the headers that may indicate if the request was proxied |
| `orig_mime_types[]` | `string` | An ordered vector of mime types from the client |
| `resp_mime_types[]` | `string` | An ordered vector of mime types from the server |
| `cookie_vars[]` | `string` | Variable names extracted from all cookies |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `method` | `string` | Verb used in the HTTP request (GET, POST, HEAD, etc.) |
| `host` | `string` | Value of the HOST header |
| `host_multihomed` | `boolean` | True if the effective host domain is associated with more than one IP address |
| `uri` | `string` | URI used in the request |
| `referrer` | `string` | Value of the “referer” header. The comment is deliberately misspelled like the standard declares, but the name used here is “referrer” spelled correctly |
| `accept` | `string` | Value of the Accept header from the client |
| `accept_encoding` | `string` | Value of the Accept-Encoding header from the client |
| `user_agent` | `string` | Value of the User-Agent header from the client |
| `request_body_len` | `bigint (quantity)` | Actual uncompressed content size of the data transferred from the client |
| `response_body_len` | `bigint (quantity)` | Actual uncompressed content size of the data transferred from the server |
| `status_code` | `int` | Status code returned by the server |
| `status_msg` | `string` | Status message returned by the server |
| `resp_filename` | `string` | The name of the file returned by the server (if any) |
| `is_proxied` | `boolean` | The connection is determined to be proxied based on HTTP header information |
| `cookie` | `string` | The content of the cookie header |
| `response_content_disposition` | `string` | The value of the Content-Disposition header (specifies names of the files to be downloaded as attachment, e.g. 'attachment; filename=”filename.jpg”') |
| `request_header_count` | `int (quantity)` | The number of headers provided in the request by the client |
| `response_header_count` | `int (quantity)` | The number of headers provided in the respose by the server |
| `orig_ip_bytes` | `decimal(20,0) (quantity)` | The number of bytes of the IP traffic from the client |
| `resp_ip_bytes` | `decimal(20,0) (quantity)` | The number of bytes of the IP traffic from the server |
| `orig_pkts` | `bigint (quantity)` | The number of packets transmitted by the client |
| `resp_pkts` | `bigint (quantity)` | The number of packets transmitted by the server |
| `request_cache_control` | `string` | The content of the Cache-Control header in the client request |
| `response_cache_control` | `string` | The content of the Cache-Control header in the server response |
| `response_expires` | `string` | The content of the Expires header in the server response |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin unique ID |
| `resp_huid` | `string` | Response unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `ja4h` | `string` | The JA4H fingerprint of the HTTP client |
| `post_data` | `binary` | Binary data of the POST request body. Truncated to 2k size |

## isession

_Latest version: `v1.5.0` (available: `v1.5.0`, `v1.4.0`, `v1.3.0`, `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | The connections client's endpoint host |
| `id.orig_p` | `int` | The connections client's endpoint port |
| `id.resp_h` | `string (ip_address)` | The connection server's endpoint host |
| `id.resp_p` | `int` | The connection server's endpoint port |
| `id.ip_ver` | `string` | no description/placeholder |
| `application[]` | `string` | Applications associated with this session |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `proto` | `smallint` | The transport layer protocol of the connection |
| `proto_name` | `string` | The name of the transport layer |
| `service` | `string` | An identification of an application protocol being sent over the connection |
| `duration` | `decimal(20,0) (quantity)` | How long, in milliseconds, the connection lasted or time until present. For 3-way or 4-way connection tear-downs, this will not include the final ACK |
| `conn_state` | `string` | The state of the connection (see https://www.zeek.org/manual/master/scripts/base/protocols/conn/main.bro.html#type-Conn::Info for values and meanings) |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_pkts` | `bigint (quantity)` | Number of packets that the originator sent |
| `orig_ip_bytes` | `decimal(20,0) (quantity)` | Number of IP level bytes that the originator sent (as seen on the wire, taken from the IP total_length header field) |
| `resp_pkts` | `bigint (quantity)` | Number of packets that the responder sent |
| `resp_ip_bytes` | `decimal(20,0) (quantity)` | Number of IP level bytes that the responder sent (as seen on the wire, taken from the IP total_length header field) |
| `resp_domain` | `string` | The domain name of the server (if any) |
| `resp_multihomed` | `boolean` | True if the domain name of the server is associated with multiple IP addresses |
| `orig_vlan_id` | `int` | VLAN_id of originator, if any |
| `resp_vlan_id` | `int` | VLAN_id of responder, if any |
| `first_orig_resp_pkt_time` | `timestamp` | Timestamp of first packet from originator to responder |
| `first_resp_orig_pkt_time` | `timestamp` | Timestamp of first packet from responder to originator |
| `first_orig_resp_data_pkt_time` | `timestamp` | Timestamp of first data packet from originator to responder |
| `first_resp_orig_data_pkt_time` | `timestamp` | Timestamp of first data packet from responder to originator |
| `session_start_time` | `timestamp` | Timestamp when session started |
| `first_orig_resp_data_pkt` | `string` | Base64 encoding of the first 16 bytes of the packet from originator to responder, represented as a string |
| `first_resp_orig_data_pkt` | `string` | Base64 encoding of the first 16 bytes of the packet from responder to originator, represented as a string |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin unique ID |
| `resp_huid` | `string` | Response unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `dir_confidence` | `smallint` | Client/server assignment confidence from 0 to 100 |
| `ja4lc` | `string` | The JA4L fingerprint of the client's light distance |
| `ja4ls` | `string` | The JA4LS fingerprint of the servers's light distance |
| `ja4t` | `string` | The JA4T fingerprint of the client's TCP SYN packet |
| `ja4ts` | `string` | The JA4TS fingerprint of the server's TCP SYN ACK packet(s) |
| `proxy_to_internal_dst` | `boolean` | True if effective destination after proxy is internal ip |
| `client_luid_proxy` | `boolean` | True if the source address of the connection has been learned as a proxy |
| `server_luid_proxy` | `boolean` | True if the destination address of the connection has been learned as a proxy |

## kerberostxn

_Latest version: `v1.3.0` (available: `v1.3.0`, `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `req_ciphers[]` | `string` | Ordered list of requested ciphers |
| `data_source` | `string` | The source of the record, either "network" or "log" |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin unique ID |
| `resp_huid` | `string` | Response unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `request_type` | `string` | Request type - Authentication Service ("AS") or Ticket Granting Service ("TGS") |
| `client` | `string` | Name of the kerberos client |
| `service` | `string` | Name of the kerberos service |
| `success` | `boolean` | True if the request was successful |
| `error_code` | `string` | The Error code (in case of failure) |
| `error_msg` | `string` | The error message (in case of failure) |
| `protocol` | `smallint` | Protocol number |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_host_observed_privilege` | `smallint` | Privilege level of host |
| `rep_cipher` | `string` | Cipher selected in reply message |
| `ticket_cipher` | `string` | Ticket cipher observed on AS-REP and TGS-REP replies |
| `as_req_padata_types[]` | `int` | PA-DATA type integers from AS-REQ messages |
| `as_req_padata_types_string[]` | `string` | Human readable PA-DATA type names for AS-REQ messages |
| `as_rep_padata_types[]` | `int` | PA-DATA type integers from AS-REP messages |
| `as_rep_padata_types_string[]` | `string` | Human readable PA-DATA type names for AS-REP messages |
| `as_req_padata_count` | `int` | Total PA-DATA entries seen on AS-REQ prior to truncation |
| `as_rep_padata_count` | `int` | Total PA-DATA entries seen on AS-REP prior to truncation |
| `account_uid` | `string` | Account UID used for this transaction |
| `service_uid` | `string` | Service UID used for this transaction, as determined by Brolator |
| `account_privilege` | `smallint` | Client's account privilege level |
| `service_privilege` | `smallint` | Privilege level of service |

## ldap

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `result[]` | `string` | The query results |
| `attributes[]` | `string` | Array of attributes used for the LDAP query |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin host local unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response host local unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_huid` | `string` | Origin host local unique ID |
| `resp_huid` | `string` | Response host local unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `message_id` | `bigint` | LDAP unique ID of the message |
| `base_object` | `string` | Path of the base object query |
| `query_scope` | `string` | The scope of the query (e.g. "baseObject") |
| `query` | `string` | The LDAP query string (e.g. "(objectclass=*)") |
| `result_code` | `string` | The result code of the LDAP query (e.g. "success" or "busy") |
| `matched_dn` | `string` | The matched Domain Name |
| `error` | `string` | The error message in case of error (e.g. "0000208D: NameErr …") |
| `duration` | `decimal(20,0) (quantity)` | The duration of the query in ms |
| `request_bytes` | `string` | The number of bytes transmitted for the request |
| `response_bytes` | `string` | The number of bytes transmitted for the response |
| `is_close` | `boolean` | Boolean flag indicating whether the close was observed |
| `is_query` | `boolean` | Boolean flag indicating whether the query was observed in the request |
| `bind_error_count` | `bigint (quantity)` | If there are bind errors, count of the errors |
| `logon_failure_error_count` | `bigint (quantity)` | The count of logon errors |
| `result_count` | `bigint (quantity)` | The count of the entries in the result |
| `encrypted_sasl_payload_count` | `bigint (quantity)` | If sasl encryption is used, the number of encrypted sasl payloads encountered |

## ntlm

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin host local unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response host local unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin host local unique ID |
| `resp_huid` | `string` | Response host local unique ID |
| `username` | `string` | Username given by the client |
| `hostname` | `string` | Hostname given by the client |
| `domain` | `string` | Domain given by the client |
| `status` | `bigint` | The status code of the operation |
| `success` | `boolean` | Indicate whether or not the authentication was successful |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |

## radius

_Latest version: `v1.3.0` (available: `v1.3.0`, `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `framed_ipv6_prefix[]` | `string` | IPv6 prefix and route to be configured for the user |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `username` | `string` | The username observed in the RADIUS message |
| `mac` | `string` | Mac address RADIUS field in the format "MM:MM:MM:SS:SS:SS" |
| `framed_address` | `string` | FQDN or IP address of requesting endpoing |
| `tunnel_client` | `string` | FQDN or IP address of tunnel initiator |
| `connect_info` | `string` | misc data about the connection, e.g., bandwidth |
| `reply_msg` | `string` | Reply message from the server challenge for the end user |
| `result` | `string` | String rep of RADIUS ResultType enum: success, failed, challenge, unknown |
| `ttl` | `decimal(20,0) (quantity)` | Duration between first request and its acknowledgment |
| `logged` | `boolean` | Inspired by Zeek's RADIUS implementation |
| `account_authentic` | `bigint` | Identifies how the user was authenticated |
| `account_delay_time` | `bigint (quantity)` | How long the sender has been trying to send the message |
| `account_input_gigawords` | `bigint (quantity)` | How many times the Acct-Input counter has rolled over |
| `account_input_octets` | `bigint (quantity)` | How many bytes have been received |
| `account_input_packets` | `bigint (quantity)` | How many packets the system has received |
| `account_output_gigawords` | `bigint (quantity)` | How many times the Acct-Output counter has rolled over |
| `account_output_octets` | `bigint (quantity)` | How many bytes have been sent |
| `account_output_packets` | `bigint (quantity)` | How many packets the system has sent |
| `account_session_id` | `string` | Unique ID that identifies the RADIUS Accounting Session |
| `account_session_time` | `bigint (quantity)` | How long the user has gotten service |
| `calling_station_id` | `string` | The identifier of the calling station, previously a phone number |
| `delegated_ipv6_prefix` | `string` | The IPv6 prefix to be delegated to the user |
| `dst_display_name` | `string` | The UI display name for server host luid |
| `dst_host_luid` | `string` | The destination host's LUID if assigned |
| `dst_luid` | `string` | Unique Id of the destination host session |
| `dst_luid_external` | `boolean` | True if dst_luid is for an external connection |
| `event_timestamp` | `timestamp` | Similar to timestamp but is the timestamp from the device, not from Vectra |
| `filter_id` | `string` | This identifies any ACL that is in use |
| `framed_interface` | `decimal(20,0)` | The suggested IPv6 Interface to be use per RFC-3162 |
| `framed_ip_address` | `string (ip_address)` | IP of the endpoint device connecting to the system |
| `framed_protocol` | `bigint` | The Framed Protocol to be used when the user connects |
| `idle_timeout` | `bigint (quantity)` | Configured idle time before disconnect |
| `nas_identifier` | `string` | Authenticating client's requesting role |
| `nas_ip_address` | `string (ip_address)` | IP of Device, Endpoint, or Intermediate System |
| `nas_port` | `bigint` | Physical port number of the Device authenticating the user |
| `nas_port_id` | `string` | Text string identifying the port provided by the client |
| `nas_port_type` | `bigint` | Type of medium of the port per RFC-2865 |
| `password_seen` | `boolean` | True if Password was observed in the RADIUS message |
| `radius_type` | `string` | RADIUS message type: Access, Accounting |
| `reply_timestamp` | `timestamp` | Epoch time in milliseconds when the reply was seen |
| `service_type` | `bigint` | The type of service requested |
| `session_timeout` | `bigint (quantity)` | The maximum session length |
| `src_display_name` | `string` | The UI display name for client host luid |
| `orig_huid` | `string` | The source host's LUID if assigned |
| `resp_huid` | `string` | Response host local unique ID |
| `src_luid` | `string` | Unique Id of the source host session |
| `src_luid_external` | `boolean` | True if src_luid is for an external connection |

## rdp

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `cookie` | `string` | Cookie value used by the client machine. This is typically a username |
| `keyboard_layout` | `string` | Keyboard layout (language) of the client machine |
| `client_build` | `string` | RDP client version used by the client machine |
| `client_name` | `string` | Name of the client machine |
| `client_dig_protocol_id` | `string` | deprecated (use Client_dig_product_id instead) |
| `client_dig_product_id` | `string` | Product ID of the client machine |
| `desktop_width` | `int (quantity)` | Desktop width of the client machine |
| `desktop_height` | `int (quantity)` | Desktop height of the client machine |
| `result` | `string` | Status result for the connection. It's a mix between RDP negotation failure messages and GCC server create response messages |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin host local unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response host local unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin host local unique ID |
| `resp_huid` | `string` | Response host local unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |

## smbfilestxn

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin host local unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response host local unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin host local unique ID |
| `resp_huid` | `string` | Response host local unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `username` | `string` | Authenticated username, if available |
| `hostname` | `string` | The hostname of the SMB client |
| `domain` | `string` | The domain name of the SMB server |
| `action` | `string` | The SMB file action (e.g. "SMB::FILE_OPEN" or "SMB::PIPE_WRITE") |
| `path` | `string` | Path pulled from the tree this file was transferred to or from |
| `name` | `string` | Filename if one was seen |
| `prev_name` | `string` | If the rename action was seen, this will be the file's previous name |
| `version` | `string` | Version of SMB for the command |
| `delete_on_close` | `boolean` | If set to true it will delete the file on close |

## smbmappingtxn

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin host local unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response host local unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin host local unique ID |
| `resp_huid` | `string` | Response host local unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `username` | `string` | Authenticated username, if available |
| `hostname` | `string` | The hostname of the SMB client |
| `domain` | `string` | The domain name of the SMB server |
| `service` | `string` | The type of resource of the tree (disk_share, printer_share, named_pipe, etc.) |
| `path` | `string` | Path pulled from the tree this file was transferred to or from |
| `version` | `string` | Version of SMB for the command |

## smtp

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `rcpt_to[]` | `string` | contents of possibly multiple SMTP "rcpt to" commands, usually the recipients of the email |
| `to[]` | `string` | list of email addresses from the To header (format "Name" <email@mail.com>) |
| `cc[]` | `string` | list of email addresses from the CC header (format "Name" <email@mail.com>) |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin host local unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response host local unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin host local unique ID |
| `resp_huid` | `string` | Response host local unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `helo` | `string` | HELO string of the client |
| `mail_from` | `string` | contents of SMTP "mail from" command, usually the sender of the email |
| `tls` | `boolean` | whether the sent mail went over TLS or not |
| `date` | `string` | The text (probably a date format) of the Date header from email headers |
| `from` | `string` | The text from the From header (format "Name" <email@mail.com>) |
| `reply_to` | `string` | Email address to send responses to |
| `msg_id` | `string` | Unique message ID of this email |
| `in_reply_to` | `string` | MsgID to which this email is replying |
| `subject` | `string` | Subject of the email |
| `user_agent` | `string` | User agent of the email client |
| `x_originating_ip` | `string` | IP that sent the email |
| `first_received` | `string` | First server that received the email in the chain of servers it followed |
| `second_received` | `string` | Second server that received the email |
| `spf_helo_status` | `string` | Sender Policy Framework - verification that the sender is legitimate (RFC 7208) |
| `spf_mail_from` | `string` | SPF can query on either of the helo string or the mailfrom address |
| `dkim_status` | `string` | DomainKeys Identified Mail - verification that the server is legitimate (RFC 6376) |
| `dmarc_status` | `string` | Domain-based Message Authentication, Reporting, and Conformance - more verification (RFC 7489) |

## ssh

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin host local unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response host local unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin host local unique ID |
| `resp_huid` | `string` | Response host local unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `version` | `string` | ssh protocol version |
| `client` | `string` | client version string |
| `server` | `string` | server version string |
| `cipher_alg` | `string` | negotiated cipher algorithm |
| `mac_alg` | `string` | negotiated mac algorithm |
| `compression_alg` | `string` | negotiated compression algorithm |
| `kex_alg` | `string` | negotiated kex algorithm |
| `host_key_alg` | `string` | negotiated host_key algorithm |
| `hassh` | `string` | Hassh fingerprint |
| `hassh_server` | `string` | Hassh server fingerprint |
| `host_key` | `string` | fingerprint of host's public key |

## ssl

_Latest version: `v1.4.0` (available: `v1.4.0`, `v1.3.0`, `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `client_extension[]` | `int` | Client extensions |
| `client_curve_num[]` | `int` | Elliptical curve number sent by the client |
| `client_ec_point_format[]` | `int` | Elliptical curve point format offered by the client |
| `server_extensions[]` | `int` | The list of server extensions supported for TLS |
| `application[]` | `string` | Applications associated with this session |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin host local unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response host local unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin unique ID |
| `resp_huid` | `string` | Response unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `server_name` | `string` | Value of the Server Name Indicator SSL/TLS extension. It indicates the server name that the client was requesting |
| `next_protocol` | `string` | Next protocol the server chose using the application layer next protocol extension, if present |
| `established` | `boolean` | Flag to indicate if this ssl session has been established successfully, or if it was aborted during the handshake |
| `cipher` | `string` | SSL/TLS cipher suite that the server chose |
| `version_num` | `int` | Numeric SSL/TLS version that the server chose |
| `version` | `string` | SSL/TLS version that the server chose |
| `curve` | `string` | Elliptic curve the server chose when using ECDH/ECDHE |
| `issuer` | `string` | Subject of the signer of the X.509 certificate offered by the server |
| `subject` | `string` | Subject of the X.509 certificate offered by the server |
| `client_issuer` | `string` | Subject of the signer of the X.509 certificate offered by the client |
| `client_subject` | `string` | Subject of the X.509 certificate offered by the client |
| `client_version_num` | `int` | Numeric SSL/TLS version that the client suggested |
| `client_version` | `string` | SSL/TLS version that the client suggested |
| `ja3` | `string` | The JA3 hash of the certificate |
| `ja3s` | `string` | The JA3S hash of the server response |
| `ja4` | `string` | The JA4 fingerprint of the TLS client |
| `ja4s` | `string` | The JA4S fingerprint of the TLS server response |
| `proxy_to_internal_dst` | `boolean` | True if effective destination after proxy is internal ip |
| `client_luid_proxy` | `boolean` | True if the source address of the connection has been learned as a proxy |
| `server_luid_proxy` | `boolean` | True if the destination address of the connection has been learned as a proxy |

## suricata

_Latest version: `v1.2.0` (available: `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | The connections client's endpoint host |
| `id.orig_p` | `int` | The connections client's endpoint port |
| `id.resp_h` | `string (ip_address)` | The connection server's endpoint host |
| `id.resp_p` | `int` | The connection server's endpoint port |
| `id.ip_ver` | `string` | no description/placeholder |
| `app_proto` | `string` | The application layer of the protocol |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_huid` | `string` | Origin unique ID |
| `resp_huid` | `string` | Response unique ID |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `alert.category` | `string` | Category of the Alert Message |
| `alert.rev` | `int` | Signature Revision Number |
| `alert.signature` | `string` | The rule name. Based on the 'msg' text in the signature |
| `alert.signature_id` | `int` | Signature Identifier |
| `alert.metadata.attack_target[]` | `string` | Specifies if the attack target is the Client, Server, Both, or Other |
| `alert.metadata.created_at[]` | `string` | Signature Revision Number |
| `alert.metadata.deployment[]` | `string` | Specifies where the signature should be deployed |
| `alert.metadata.malware_family[]` | `string` | Specifies the Malware Family that is associated with the signature |
| `alert.metadata.tag[]` | `string` | Specifies any tag information assigned to the signature by the author |
| `alert.metadata.updated_at[]` | `string` | Specifies the data of the last update to the signature |
| `alert.metadata.signature_severity[]` | `string` | Specifies the severity defined for a given signature |
| `payload` | `string` | Base64 Encoded packet payload information |
| `payload_printable` | `string` | The payload presented in ASCII |
| `packet` | `string` | The packet that triggered the signature. |
| `flow` | `string` | The Suricata Network Flow Information |
| `direction` | `string` | The traffic direction of the alert |
| `dns` | `string` | Contains all information about resolved DNS in the traffic |
| `anomaly` | `string` | Contains information related to Anomaly detections |
| `http` | `string` | Contains information related to the HTTP Header fields |
| `ftp` | `string` | Contains information about the observed FTP control channel attributes |
| `ftp_data` | `string` | Contains information about the FTP data channel attributes |
| `tls` | `string` | Contains information about the SSL/TLS Certificates |
| `tftp` | `string` | Contains information about TFTP transactions |
| `smb` | `string` | Contains information about SMB transactions |
| `bittorrent_dht` | `string` | Contains information about Bittorrent Distributed Hash Tables |
| `ssh` | `string` | Contains information about SSH sessions |
| `rdp` | `string` | Contains information about the Remote Desktop Protocol |
| `rfb` | `string` | Contains information about the Remote Frame Buffer protocol used by VNC and other clients |
| `mqtt` | `string` | Contains information about the MQTT protocol |
| `http2` | `string` | Contains information related to HTTP version 2 Connections |
| `pgsql` | `string` | Contains information related to PostgresSQL Connections |
| `ike` | `string` | Contains information about IKE VPN negotiations |
| `modbus` | `string` | Contains information about the Modbus Industrial Control System Protocol |
| `quic` | `string` | Contains information about QUIC negotiations |
| `dhcp` | `string` | Contains information about DHCP transactions |

## x509

_Latest version: `v1.3.0` (available: `v1.3.0`, `v1.2.0`, `v1.1.0`, `v1.0.0`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `id.orig_h` | `string (ip_address)` | Originating endpoint IP address |
| `id.orig_p` | `int` | Originating endpoint TCP/UDP port |
| `id.resp_h` | `string (ip_address)` | Responding endpoint IP address |
| `id.resp_p` | `int` | Responding endpoint TCP/UDP port |
| `id.ip_ver` | `string` | IP Version |
| `certificate.version` | `int` | Version number |
| `certificate.serial` | `string` | Serial number |
| `certificate.subject` | `string` | Certificate subject |
| `certificate.issuer` | `string` | Certificate issuer |
| `certificate.self_issued` | `boolean` | True if the certificate is marked as self issued |
| `certificate.cn` | `string` | Last (most specific) common name |
| `certificate.not_valid_before` | `decimal(20,0) (quantity)` | Timestamp before when certificate is not valid |
| `certificate.not_valid_after` | `decimal(20,0) (quantity)` | Timestamp after when certificate is not valid |
| `certificate.key_alg` | `string` | Name of the key algorithm |
| `certificate.sig_alg` | `string` | Name of the signature algorithm |
| `certificate.key_type` | `string` | Key type, if key parseable by openssl (either rsa, dsa or ec) |
| `certificate.key_length` | `string` | Key length in bits |
| `certificate.exponent` | `string` | Exponent, if RSA-certificate |
| `certificate.curve` | `string` | Curve, if EC-certificate |
| `basic_constraints.ca` | `boolean` | CA flag set |
| `basic_constraints.path_len` | `decimal(20,0) (quantity)` | Maximum path length |
| `san.email[]` | `string` | List of email entries in SAN (SubjectAlternativeName) |
| `san.dns[]` | `string` | List of DNS entries in SAN |
| `san.uri[]` | `string` | List of URI entries in SAN |
| `san.ip[]` | `string (ip_address)` | List of IP entries in SAN |
| `san.other_fields` | `boolean` | True if the certificate contained other, not recognized or parsed name fields |
| `application[]` | `string` | Applications associated with this session |
| `timestamp` | `timestamp` | Timestamp for when the event happened (in ms) |
| `uid` | `string` | Identifier that combines Sensor ID and Session ID |
| `sensor_uid` | `string` | Unique ID of the sensor |
| `local_orig` | `boolean` | True if the client is in the local network |
| `local_resp` | `boolean` | True if the server is in the local network |
| `orig_hostname.name` | `string` | Origin hostname |
| `orig_hostname.host_luid` | `string` | Origin host local unique ID |
| `orig_hostname.id` | `int` | Vectra internal identifier for an origin host |
| `resp_hostname.name` | `string` | Response hostname |
| `resp_hostname.host_luid` | `string` | Response host local unique ID |
| `resp_hostname.id` | `int` | Vectra internal identifier for a response host |
| `orig_sluid` | `string` | Unique ID for the originating host session, used to track a unique IP session over time. |
| `resp_sluid` | `string` | Unique ID for the responding host session, used to track a unique IP session over time. |
| `ja4x` | `string` | The JA4X fingerprint of the X.509 TLS certificate |
| `proxy_to_internal_dst` | `boolean` | True if effective destination after proxy is internal ip |
| `client_luid_proxy` | `boolean` | True if the source address of the connection has been learned as a proxy |
| `server_luid_proxy` | `boolean` | True if the destination address of the connection has been learned as a proxy |
