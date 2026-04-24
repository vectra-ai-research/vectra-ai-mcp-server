# Microsoft Azure (Control Plane) Schemas

Schemas for Microsoft Azure control plane and resource telemetry (insights logs, flow logs, operations, PIM, storage accounts, third-party applications).

Notation:

- Nested struct fields use dotted paths, e.g. `id.orig_h`.
- Arrays are marked with `[]` on the parent segment, e.g. `resources[].arn`.
- The `Type` column shows the underlying scalar type; when a `usage` hint is present in the schema it is appended in parentheses, e.g. `string (ip_address)`.

## Metadata Types

- [`flowlogs`](#flowlogs)
- [`insightsactivitylogs`](#insightsactivitylogs)
- [`insightslogsauditevent`](#insightslogsauditevent)
- [`insightslogsfunctionapplogs`](#insightslogsfunctionapplogs)
- [`insightslogsjoblogs`](#insightslogsjoblogs)
- [`insightslogsjobstreams`](#insightslogsjobstreams)
- [`operations`](#operations)

## flowlogs

| Attribute | Type | Description |
| --- | --- | --- |
| `time` | `string` | Time in UTC when the event was logged |
| `flowlogguid` | `string` | Resource GUID of the FlowLog resource |
| `macaddress` | `string` | MAC address of the network interface where the event was captured |
| `category` | `string` | Log category (constant: FlowLogFlowEvent) |
| `flowlogresourceid` | `string` | Resource ID of the FlowLog resource |
| `targetresourceid` | `string` | Resource ID of the target resource that's associated with the FlowLog resource. |
| `flowlogversion` | `string` | Flow log version |
| `operationname` | `string` | Operation name (constant: FlowLogFlowEvent) |
| `aclid` | `string` | Identifier of the resource that's evaluating traffic, either a network security group or Virtual Network Manager. For traffic that's denied because of encryption, this value is unspecified |
| `rule` | `string` | Name of the rule that allowed or denied the traffic. For traffic that's denied because of encryption, this value is unspecified |
| `timestamp` | `timestamp` | Time stamp of when the flow occurred, in UNIX epoch format. (main timestamp field) |
| `srcip` | `string` | Source IP address |
| `dstip` | `string` | Destination IP address |
| `srcport` | `int` | Source port |
| `dstport` | `int` | Destination port |
| `protocol` | `int` | Layer 4 protocol of the flow, expressed in IANA assigned values. |
| `flowdir` | `string` | Direction of the traffic flow relative to the NIC which is logging the traffic. Valid values are I for inbound and O for outbound. |
| `flowstate` | `string` | State of the flow. Possible states are: 'B': Begin, when a flow is created. No statistics are provided, 'C': Continuing for an ongoing flow. Statistics are provided at five-minute intervals, 'E': End, when a flow is terminated. Final statistics are provided, 'D': Denied, when a flow is denied |
| `flowencryption` | `string` | Encryption state of the flow. Possible values are: 'X': Connection is encrypted, 'NX': Connection is unencrypted. This is the default for traffic in virtual networks, 'NX_HW_NOT_SUPPORTED': Hardware is unsupported, 'NX_NOT_ACCEPTED': Drop due to no encryption, 'NX_NOT_SUPPORTED': Discovery is unsupported, 'NX_LOCAL_DST': Destination is on the same host, 'NX_FALLBACK': Fall back to no encryption, configured with the Allow unencrypted policy for both source and destination endpoints |
| `pktssent` | `int` | Total number of packets sent from the source to the destination since the last update. |
| `bytessent` | `int` | Total number of packet bytes sent from the source to the destination since the last update. Packet bytes include the packet header and payload. |
| `pktsrecv` | `int` | Total number of packets sent from the destination to the source since the last update. |
| `bytesrecv` | `int` | Total number of packet bytes sent from the destination to the source since the last update. Packet bytes include the packet header and payload. |

## insightsactivitylogs

| Attribute | Type | Description |
| --- | --- | --- |
| `time` | `string` | The timestamp (UTC) of the event |
| `rolelocation` | `string` | The location where the role operation occurred |
| `releaseversion` | `string` | The version of the Azure service release |
| `resourceid` | `string` | The resource ID of the Azure resource that emitted the event |
| `operationname` | `string` | The name of the operation that this event represents |
| `category` | `string` | The log category of the event |
| `resulttype` | `string` | The status of the event (Success, Failure, etc.) |
| `resultsignature` | `string` | The substatus of the event, typically an HTTP status code |
| `durationms` | `string` | The duration of the operation in milliseconds |
| `calleripaddress` | `string` | The IP address of the caller that initiated the operation |
| `correlationid` | `string` | A GUID used to group together related events |
| `identity.authorization.scope` | `string` | The scope of the authorization (subscription, resource group, or resource) |
| `identity.authorization.action` | `string` | The action that was authorized to be performed |
| `identity.authorization.evidence.role` | `string` | The role name used for the operation |
| `identity.authorization.evidence.roleassignmentscope` | `string` | The scope where the role assignment is effective |
| `identity.authorization.evidence.roleassignmentid` | `string` | The unique identifier of the role assignment |
| `identity.authorization.evidence.roledefinitionid` | `string` | The unique identifier of the role definition |
| `identity.authorization.evidence.principalid` | `string` | The unique identifier of the principal (user, group, or service principal) |
| `identity.authorization.evidence.principaltype` | `string` | The type of principal (User, Group, ServicePrincipal, etc.) |
| `identity.claims.aud` | `string` | Audience - identifies the intended recipient of the token |
| `identity.claims.iss` | `string` | Issuer - identifies the security token service (STS) that issued the token |
| `identity.claims.iat` | `string` | Issued At - the time when the token was issued |
| `identity.claims.nbf` | `string` | Not Before - the time before which the token is not valid |
| `identity.claims.exp` | `string` | Expiration Time - the time after which the token expires |
| `identity.claims.aio` | `string` | Azure AD internal claim for token optimization |
| `identity.claims.appid` | `string` | Application ID of the client using the token |
| `identity.claims.appidacr` | `string` | Application authentication context class reference |
| `identity.claims.idtyp` | `string` | Identity type (app, user, etc.) |
| `identity.claims.rh` | `string` | Request hash for token validation |
| `identity.claims.uti` | `string` | Unique token identifier |
| `identity.claims.ver` | `string` | Token version |
| `identity.claims.xms_cae` | `string` | Continuous Access Evaluation claim |
| `identity.claims.xms_mirid` | `string` | Managed Identity resource ID |
| `identity.claims.xms_tcdt` | `string` | Tenant creation date time |
| `identity.claims.groups` | `string` | Group memberships of the authenticated user |
| `identity.claims.ipaddr` | `string` | IP address of the client |
| `identity.claims.name` | `string` | Display name of the authenticated user |
| `identity.claims.puid` | `string` | Passport Unique ID - unique identifier for the user |
| `level` | `string` | The severity level of the event (Informational, Warning, Error, or Critical) |
| `properties.requestbody` | `string` | The body of the HTTP request that triggered the event |
| `properties.eventcategory` | `string` | The category classification of the event |
| `properties.entity` | `string` | The entity or resource that was the target of the operation |
| `properties.message` | `string` | A human-readable message describing the event |
| `properties.hierarchy` | `string` | The hierarchical path or structure related to the event |
| `properties.statuscode` | `string` | The HTTP status code returned by the operation |
| `properties.servicerequestid` | `int` | The unique identifier for the service request |
| `tenantid` | `string` | The tenant ID associated with the event |
| `jobid` | `string` | The unique identifier of the job that generated this event |
| `jobtype` | `string` | The type or category of the job |
| `timestamp` | `timestamp` | Event timestamp |

## insightslogsauditevent

| Attribute | Type | Description |
| --- | --- | --- |
| `time` | `string` | _(no description)_ |
| `category` | `string` | _(no description)_ |
| `operationname` | `string` | _(no description)_ |
| `resulttype` | `string` | _(no description)_ |
| `correlationid` | `string` | _(no description)_ |
| `calleripaddress` | `string` | _(no description)_ |
| `identity.claim.oid` | `string` | _(no description)_ |
| `identity.claim.appid` | `string` | _(no description)_ |
| `identity.claim.appidacr` | `string` | _(no description)_ |
| `identity.claim.xms_mirid` | `string` | _(no description)_ |
| `identity.claim.xms_az_nwperimid[]` | `int` | _(no description)_ |
| `properties.id` | `string` | _(no description)_ |
| `properties.clientinfo` | `string` | _(no description)_ |
| `properties.httpstatuscode` | `bigint` | _(no description)_ |
| `properties.requesturi` | `string` | _(no description)_ |
| `properties.isaccesspolicymatch` | `boolean` | _(no description)_ |
| `properties.tlsversion` | `string` | _(no description)_ |
| `resourceid` | `string` | _(no description)_ |
| `operationversion` | `string` | _(no description)_ |
| `resultsignature` | `string` | _(no description)_ |
| `durationms` | `string` | _(no description)_ |
| `timestamp` | `timestamp` | _(no description)_ |

## insightslogsfunctionapplogs

| Attribute | Type | Description |
| --- | --- | --- |
| `time` | `string` | _(no description)_ |
| `resourceid` | `string` | _(no description)_ |
| `category` | `string` | _(no description)_ |
| `operationname` | `string` | _(no description)_ |
| `level` | `string` | _(no description)_ |
| `location` | `string` | _(no description)_ |
| `properties.appname` | `string` | _(no description)_ |
| `properties.roleinstance` | `string` | _(no description)_ |
| `properties.message` | `string` | _(no description)_ |
| `properties.category` | `string` | _(no description)_ |
| `properties.hostversion` | `string` | _(no description)_ |
| `properties.functioninvocationid` | `string` | _(no description)_ |
| `properties.functionname` | `string` | _(no description)_ |
| `properties.hostinstanceid` | `string` | _(no description)_ |
| `properties.level` | `string` | _(no description)_ |
| `properties.levelid` | `bigint` | _(no description)_ |
| `properties.processid` | `bigint` | _(no description)_ |
| `properties.eventid` | `bigint` | _(no description)_ |
| `properties.eventname` | `string` | _(no description)_ |
| `properties.exceptiondetails` | `string` | _(no description)_ |
| `properties.exceptionmessage` | `string` | _(no description)_ |
| `properties.exceptiontype` | `string` | _(no description)_ |
| `timestamp` | `timestamp` | _(no description)_ |

## insightslogsjoblogs

| Attribute | Type | Description |
| --- | --- | --- |
| `tenant` | `string` | _(no description)_ |
| `time` | `string` | _(no description)_ |
| `resourceid` | `string` | _(no description)_ |
| `operationname` | `string` | _(no description)_ |
| `resulttype` | `string` | _(no description)_ |
| `resultdescription` | `string` | _(no description)_ |
| `correlationid` | `string` | _(no description)_ |
| `properties.runbookname` | `string` | _(no description)_ |
| `properties.jobid` | `string` | _(no description)_ |
| `properties.caller` | `string` | _(no description)_ |
| `properties.parameters` | `int` | _(no description)_ |
| `properties.runon` | `string` | _(no description)_ |
| `category` | `string` | _(no description)_ |
| `timestamp` | `timestamp` | _(no description)_ |

## insightslogsjobstreams

_Latest version: `v0.0.1` (available: `v0.0.1`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `tenant` | `string` | _(no description)_ |
| `time` | `string` | _(no description)_ |
| `resourceid` | `string` | _(no description)_ |
| `operationname` | `string` | _(no description)_ |
| `resulttype` | `string` | _(no description)_ |
| `resultdescription` | `string` | _(no description)_ |
| `correlationid` | `string` | _(no description)_ |
| `properties.runbookname` | `string` | _(no description)_ |
| `properties.jobid` | `string` | _(no description)_ |
| `properties.caller` | `int` | _(no description)_ |
| `properties.streamtype` | `string` | _(no description)_ |
| `properties.runon` | `string` | _(no description)_ |
| `category` | `string` | _(no description)_ |
| `timestamp` | `timestamp` | _(no description)_ |

## operations

_Latest version: `v1.1.0` (available: `v1.1.0`, `v1.0.0`, `v0.0.1`)_

| Attribute | Type | Description |
| --- | --- | --- |
| `time` | `string` | The timestamp (UTC) of the event |
| `tenantid` | `string` | The tenant ID associated with the event |
| `resourceid` | `string` | The resource ID of the resource that emitted the event |
| `operationname` | `string` | The name of the operation that this event represents |
| `operationversion` | `string` | The API version associated with the operation |
| `category` | `string` | The log category of the event |
| `resulttype` | `string` | The status of the event |
| `resultsignature` | `string` | The substatus of the event. If this operation corresponds to a REST API call, this field is the HTTP status code of the corresponding REST call |
| `resultdescription` | `string` | The static text description of this operation |
| `durationms` | `string` | The duration of the operation in milliseconds |
| `calleripaddress` | `string` | The caller IP address, if the operation corresponds to an API call that would come from an entity with a publicly available IP address |
| `correlationid` | `string` | A GUID that’s used to group together a set of related events |
| `identity` | `string (JSONDocument)` | A JSON blob that describes the identity of the user or application that performed the operation |
| `level` | `string` | The severity level of the event. Must be one of Informational, Warning, Error, or Critical |
| `location` | `string` | The region of the resource emitting the event. Only valid for resource logs |
| `properties` | `string (JSONDocument)` | Any extended properties related to this category of events. All custom or unique properties must be put inside this 'Part B' of the schema |
| `objectid` | `string` | The object ID of the entity which performed the operation |
| `subscription` | `string` | The subscription ID of the resource which emitted the event |
| `applicationid` | `string` | The application ID for the app that was used to perform the operation |
| `applicationname` | `string` | The application name for the app that was used to perform the operation |
| `resourcegroup` | `string` | The resource group containing the resource which emitted the event |
| `roleid` | `string` | The ID of the role used for an operation |
| `rolescope` | `string` | The scope of the role used for the operation |
| `rolename` | `string` | The name of the role used for the operation |
| `timestamp` | `timestamp` | Event timestamp |
| `actor.name` | `string` | Actor: identity which has performed the operation |
| `actor.objectid` | `string` | Canonical ID |
| `actor.id` | `int` | Reference in VUI |
| `vectra.identity.name` | `string` | Identity which has performed or is a target of the operation |
| `vectra.identity.objectid` | `string` | Canonical ID |
| `vectra.identity.id` | `int` | Reference in VUI |
