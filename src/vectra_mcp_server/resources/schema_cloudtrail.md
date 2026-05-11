# AWS CloudTrail Schemas

Schemas for AWS CloudTrail events.

Notation:

- Nested struct fields use dotted paths, e.g. `id.orig_h`.
- Arrays are marked with `[]` on the parent segment, e.g. `resources[].arn`.
- The `Type` column shows the underlying scalar type; when a `usage` hint is present in the schema it is appended in parentheses, e.g. `string (ip_address)`.

## Metadata Types

- [`cloudtrail`](#cloudtrail)

## cloudtrail

| Attribute | Type | Description |
| --- | --- | --- |
| `timestamp` | `timestamp` | Time when the event happened |
| `event_version` | `string` | The version of the CloudTrail log event format |
| `user_identity.type` | `string` | The type of the identity. Examples: Root, IAMUser, AssumedRole, Role, FederatedUser, etc |
| `user_identity.principal_id` | `string` | A unique identifier for the entity that made the call |
| `user_identity.arn` | `string` | The Amazon Resource Name (ARN) of the principal that made the call. The last section of the arn contains the user or role that made the call |
| `user_identity.account_id` | `string` | The account that owns the entity that granted permissions for the request |
| `user_identity.access_key_id` | `string` | The access key ID that was used to sign the request |
| `user_identity.session_context.session_issuer.type` | `string` | If the request was made with temporary security credentials, sessionContext provides information about the session that was created for those credentials.  In this case, the identity type |
| `user_identity.session_context.session_issuer.principal_id` | `string` | If the request was made with temporary security credentials, sessionContext provides information about the session that was created for those credentials; in this case, a unique identifier for the entity that made the call |
| `user_identity.session_context.session_issuer.arn` | `string` | If the request was made with temporary security credentials, sessionContext provides information about the session that was created for those credentials; in this case, The Amazon Resource Name (ARN) of the principal that made the call. The last section of the arn contains the user or role that made the call |
| `user_identity.session_context.session_issuer.account_id` | `string` | If the request was made with temporary security credentials, sessionContext provides information about the session that was created for those credentials; in this case, the account that owns the entity that granted permissions for the request |
| `user_identity.session_context.session_issuer.user_name` | `string` | If the request was made with temporary security credentials, sessionContext provides information about the session that was created for those credentials; in this case, the friendly name of the identity that made the call |
| `user_identity.session_context.attributes.mfa_authenticated` | `string` | If the request was made with temporary security credentials, sessionContext provides information about the session that was created for those credentials; in this case, if the root user or IAM user whose credentials were used for the request also was authenticated with an MFA device |
| `user_identity.session_context.attributes.creation_date` | `timestamp` | If the request was made with temporary security credentials, sessionContext provides information about the session that was created for those credentials; in this case, the date and time when the temporary security credentials were issued |
| `user_identity.session_context.ec2_role_delivery` | `string` | The version of the IMDS API used to retrieve credentials for an EC2. This is only applicable for ec2 instances. It can be null, 1, or 2 |
| `user_identity.session_context.source_identity` | `string` | The source identity information for the session context |
| `user_identity.user_name` | `string` | The friendly name of the identity that made the call |
| `user_identity.invoked_by` | `string` | The name of the AWS service that made the request, such as Amazon EC2 Auto Scaling or AWS Elastic Beanstalk |
| `event_time` | `timestamp` | This field displays the date and time when this request was made |
| `event_source` | `string` | The service that the request was made to. This name is typically a short form of the service name without spaces plus .amazonaws.com |
| `event_name` | `string` | The requested action, which is one of the actions in the API for that service |
| `aws_region` | `string` | The AWS region that the request was made to, such as us-east-2 |
| `source_ip_address` | `string (ip_address)` | The IP address that the request was made from. For actions that originate from the service console, the address reported is for the underlying customer resource, not the console web server. When a service is accessed on behalf of a console user ip address of "AWS_INTERNAL" is used |
| `user_agent` | `string` | The agent through which the request was made, such as the AWS Management Console, an AWS service, the AWS SDKs or the AWS CLI |
| `request_parameters` | `string` | The parameters, if any, that were sent with the request |
| `request_source_identity.value` | `string` | _(no description)_ |
| `assume_role_role_arn` | `string` | The role ARN request parameter for an AssumeRole event |
| `response_elements` | `string` | The response element for actions that make changes (create, update, or delete actions) |
| `request_id` | `string` | The value that identifies the request. The service being called generates this value |
| `event_id` | `string` | GUID generated by CloudTrail to uniquely identify each event |
| `resources[].arn` | `string` | ARN of resource(s) accessed in the event |
| `resources[].account_id` | `string` | Account ID of the resource owner |
| `resources[].type` | `string` | Resource type identifier in the format: AWS::aws-service-name::data-type-name |
| `event_type` | `string` | Identifies the type of event that generated the event record |
| `recipient_account_id` | `string` | Represents the account ID that received this event |
| `shared_event_id` | `string` | GUID generated by CloudTrail to uniquely identify CloudTrail events from the same AWS action that is sent to different AWS accounts |
| `error_code` | `string` | The AWS service error code, if the request returns an error |
| `error_message` | `string` | If the request returns an error, the description of the error |
| `api_version` | `string` | Identifies the API version associated with the AwsApiCalleventType value |
| `read_only` | `string` | Identifies whether this operation is a read-only operation |
| `additional_event_data` | `string` | Additional data about the event that was not part of the request or response |
| `vpc_endpoint_id` | `string` | Identifies the VPC endpoint in which requests were made from a VPC to another AWS service, such as Amazon S3 |
| `event_category` | `string` | Shows the event category that is used in LookupEvents calls |
| `session_credential_from_console` | `bool` | Shows whether or not an event originated from an AWS Management Console session |
| `management_event` | `string` | A Boolean value that identifies whether the event is a management event |
| `service_event_details` | `string` | Identifies the service event, including what triggered the event and the result |
| `vectra.entity.resolved_identity.identity_type` | `string` | Identity type of the original user identity before any other roles were assumed |
| `vectra.entity.resolved_identity.canonical_name` | `string` | Name of the Kingpin Attributed entity which performed this action, regardless of roles assumed |
| `vectra.entity.resolved_identity.account_id` | `string` | IAM user account_id before any other roles were assumed |
| `vectra.entity.resolved_identity.principal_id` | `string` | Principal ID of the IAM user before any other roles were assumed |
| `vectra.entity.resolved_identity.user_name` | `string` | Username associated to the IAM user, before any other roles were assumed |
| `vectra.entity.resolved_identity.arn` | `string` | IAM user ARN before any other roles were assumed |
| `vectra.entity.resolved_identity.invoked_by` | `string` | Resolved identity of the AWS Service (null if it's not a service) |
| `vectra.entity.resolved_identity.aws_region` | `string` | The AWS region where the original action was taken by the resolved identity |
| `vectra.entity.role_chain[].arn` | `string` | The ARN of the first role the user automatically assumed, before any other roles were assumed |
| `vectra.entity.role_chain[].principal_id` | `string` | The principal ID of the role session, which includes the principal ID of the role and the name of the role session separated by a colon |
| `vectra.entity.role_chain[].creation_date` | `timestamp` | The creation date of the role session. Basically, the date and time when the role was assumed |
| `vectra.entity.role_chain[].role_session_name` | `string` | The role session's session name |
| `vectra.entity.role_chain[].aws_access_key` | `string` | The role session's access key id |
