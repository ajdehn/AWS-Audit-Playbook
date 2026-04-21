## Control Description
Web Application Firewall (WAF) is configured to protect Application Load Balancers and API Gateways.

## Example Risk
Malicious actors use SQL injection prompts to gain unauthorized access to the production web applicaiton.

## Test Procedures
1. Obtained a list of WAFv2 Web ACLs for each in-scope region by calling the [list_web_acls()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/wafv2/client/list_web_acls.html) boto3 command with `Scope="REGIONAL"`.
2. Saved the list of Web ACLs in the audit evidence folder. See [wafv2/[region]/web_acls.json](/evidence_library/wafv2/us-east-2/web_acls.json).
3. For each Web ACL, obtained the list of associated Application Load Balancers by calling the [list_resources_for_web_acl()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/wafv2/client/list_resources_for_web_acl.html) boto3 command with `ResourceType="APPLICATION_LOAD_BALANCER"`.
4. Saved the associated Application Load Balancer ARNs for each Web ACL. See [wafv2/[region]/[web_acl_name]/resources_alb.json](/evidence_library/wafv2/us-east-2/example-acl/resources_alb.json).
5. For each Web ACL, obtained the list of associated API Gateway stages by calling the [list_resources_for_web_acl()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/wafv2/client/list_resources_for_web_acl.html) boto3 command with `ResourceType="API_GATEWAY"`.
6. Saved the associated API Gateway ARNs for each Web ACL. See [wafv2/[region]/[web_acl_name]/resources_apigw.json](/evidence_library/wafv2/us-east-2/example-acl/resources_apigw.json).
7. Obtained a list of Application Load Balancers by calling the [describe_load_balancers()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2/client/describe_load_balancers.html) boto3 command.
8. Saved the list of load balancers in the audit evidence folder. See [ELBv2/[region]/load_balancers.json](/evidence_library/ELBv2/us-east-2/load_balancers.json).
9. Inspected each Application Load Balancer to determine whether its ARN exists in any Web ACL associated resource list.
10. Obtained a list of API Gateways by calling the [get_rest_apis()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigateway/client/get_rest_apis.html) boto3 command.
11. Saved the list of API Gateways in the audit evidence folder. See [APIGateway/[region]/rest_apis.json](/evidence_library/APIGateway/us-east-2/rest_apis.json).
12. Inspected each API Gateway to determine whether any associated stage ARN exists in the Web ACL associated resource lists.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)
- [AWS WAF Developer Guide – Associating a Web ACL with AWS Resources](https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works-resources.html)