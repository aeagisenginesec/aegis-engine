# Aegis AWS Coverage Matrix

**Date:** 2026-10-11
**AWS rules:** 245 | **Resource types:** 131 | **Test functions:** 500+

Systematic inventory of AWS detection coverage organized by the 8 roadmap
threat categories. This matrix guides future rule development — gaps are
ranked by (severity × prevalence × exploitability).

---

## 1. IAM and Privilege Escalation

| Sub-area | Rules | Resource types |
|----------|-------|----------------|
| Wildcard admin | 006 (Critical), 333 (High), 422 (High) | aws_iam_policy, aws_iam_role_policy, aws_iam_user_policy, aws_iam_group_policy, aws_ssoadmin_permission_set_inline_policy |
| Trust policies | 101 (Critical), 102 (High) | aws_iam_role |
| Privilege escalation chains | 501 (Critical), 502 (Critical), 503 (High), 504 (High), 505 (High) | aws_iam_policy, aws_iam_role_policy, aws_iam_user_policy |
| Password policy | 334 (Medium), 388 (Medium) | aws_iam_account_password_policy, aws_cognito_user_pool |
| MFA / auth hardening | 387 (Medium), 389 (Medium), 421 (High) | aws_cognito_user_pool, aws_cognito_identity_pool |
| Service-specific IAM | 526 (Medium — SageMaker) | aws_iam_policy |

**Threats covered:** Wildcard `*` admin, open trust policies (`*` principal),
privilege escalation via `iam:CreatePolicy`+`iam:AttachRolePolicy`,
`iam:PassRole`+`ec2:RunInstances` credential exposure, data exfiltration
primitives, unconstrained IAM write actions, weak password policies, Cognito
misconfigurations, unauthenticated identity pools.

**Gaps:**
| Priority | Gap | Suggested ID |
|----------|-----|--------------|
| High | IAM user with access keys older than 90 days (no rotation) | AEGIS-AWS-552 |
| High | IAM policy with `NotAction`+`Allow` (deny-bypass pattern) | AEGIS-AWS-553 |
| Medium | IAM role with excessive session duration (>12h) | AEGIS-AWS-554 |
| Medium | IAM group with inline admin policy (groups should use managed) | AEGIS-AWS-555 |
| Low | IAM user without MFA device (Terraform-provable via `aws_iam_user` tags is weak — needs IAM API) | — (not Terraform-provable) |

**Coverage score: 8/10** — strongest category. Privilege escalation analysis
(501–505) is a differentiator vs Checkov.

---

## 2. Networking

| Sub-area | Rules | Resource types |
|----------|-------|----------------|
| Security groups | 004 (High), 005 (Medium), 397 (Medium), 533 (Medium), 604 (Low) | aws_security_group, aws_default_security_group, aws_security_group_rule, aws_vpc_security_group_ingress_rule, aws_vpc_security_group_egress_rule |
| Load balancers | 201 (High), 202 (Critical), 203 (High), 323 (Medium), 324 (High), 329 (High), 371 (Medium), 401 (High), 402 (Medium), 444 (High — EC2 public IP), 506 (High), 510 (Medium), 609 (Low) | aws_lb, aws_alb, aws_elb, aws_lb_listener, aws_alb_listener |
| VPC / subnets | 205 (High), 209 (Medium), 396 (Medium), 398 (Medium), 400 (Medium) | aws_subnet, aws_vpc, aws_vpc_peering_connection |
| NACLs | 328 (Medium), 331 (Medium) | aws_network_acl, aws_network_acl_rule |
| VPC endpoints | 433 (High), 442 (Medium) | aws_vpc_endpoint, aws_vpc_endpoint_service |
| CloudFront / edge | 325 (High), 330 (Medium), 405 (High), 512 (Medium), 529 (Low), 625 (Low) | aws_cloudfront_distribution |
| API Gateway | 326 (High), 327 (Medium), 332 (Medium), 372 (High), 403 (High), 404 (High), 410 (High) | (apigateway resources) |
| AppSync | 373 (Medium), 374 (Medium), 513 (Medium), 614 (Low) | aws_appsync_graphql_api |
| Attack paths | 103 (High), 105 (High) | cross-resource |
| WAF | 330 (Medium), 378 (High), 506 (High), 513 (Medium), 530 (Low), 531 (Low), 613 (Low) | aws_wafv2_web_acl |
| Transfer | 379 (High), 380 (Medium), 509 (High), 520 (Medium) | aws_transfer_server |

**Threats covered:** Open ingress/egress, plaintext HTTP listeners, weak TLS,
internet-facing LBs without WAF, public subnets, default VPC/SG usage,
NACL misconfigurations, CloudFront HTTP/WAF gaps, API Gateway unauthenticated
routes, overly permissive CORS, multi-hop attack paths (internet → SG → SG → RDS).

**Gaps:**
| Priority | Gap | Suggested ID |
|----------|-----|--------------|
| High | Transit Gateway with default route table propagation (overly permissive routing) | AEGIS-AWS-556 |
| Medium | VPC endpoint policy allows `*` principal (beyond 433's public check) | AEGIS-AWS-557 |
| Medium | ALB with access logs disabled cross-zone (have 371/609 for access logs; gap is `access_logs` block present but misconfigured bucket) | — (edge case) |
| Low | Direct Connect / VPN tunnel without BGP encryption | — (rare in Terraform) |

**Coverage score: 9/10** — most comprehensive category. Multi-hop attack paths
(105) are a key differentiator.

---

## 3. S3 and Data Protection

| Sub-area | Rules | Resource types |
|----------|-------|----------------|
| Encryption | 001 (High), 414 (High) | aws_s3_bucket, aws_s3_account_public_access_block |
| Public exposure | 002 (High), 003 (Critical), 104 (Critical), 206 (High), 415 (High), 441 (High) | aws_s3_bucket, aws_s3_bucket_acl, aws_s3_bucket_policy, aws_s3control_access_point_policy, aws_s3_account_public_access_block |
| Versioning / logging | 012 (Medium), 445 (Medium) | aws_s3_bucket, aws_s3_bucket_versioning, aws_s3_bucket_logging |
| TLS enforcement | 443 (High) | aws_s3_bucket_policy |
| Hygiene | 601 (Low), 602 (Low), 603 (Low) | aws_s3_bucket |

**Threats covered:** Unencrypted buckets, public ACLs, public bucket policies,
missing public access blocks, account-level PAB disabled, S3 exfiltration
attack paths, TLS enforcement, access logging, versioning.

**Gaps:**
| Priority | Gap | Suggested ID |
|----------|-----|--------------|
| Medium | S3 bucket without Object Lock (compliance/immutability) | AEGIS-AWS-558 |
| Low | S3 bucket without inventory configuration | AEGIS-AWS-559 |
| Low | S3 bucket with `force_destroy = true` (data loss risk) | AEGIS-AWS-560 |

**Coverage score: 9/10** — excellent. Core S3 threats fully covered.

---

## 4. KMS and Secrets

| Sub-area | Rules | Resource types |
|----------|-------|----------------|
| KMS keys | 335 (High), 420 (High) | aws_kms_key |
| Secrets Manager | 337 (Medium), 425 (High) | aws_secretsmanager_secret_rotation, aws_secretsmanager_secret_version |
| SSM parameters | 338 (High) | aws_ssm_parameter |
| Hardcoded credentials | 339 (High), 534 (Critical), 535 (High), 536 (High), 537 (Medium), 538 (High), 539 (Medium) | aws_db_instance, terraform_variable, terraform_locals, terraform_output, EC2 user_data |
| ElastiCache access | 428 (High) | (elasticache user) |

**Threats covered:** KMS without rotation, public KMS policies, long rotation
intervals, plaintext SSM secrets, hardcoded credentials (with taint tracking
through `var.*`/`local.*`), secrets in user_data (base64-decoded), provisioner
connections, Terraform outputs, tags, variable defaults, locals.

**Gaps:**
| Priority | Gap | Suggested ID |
|----------|-----|--------------|
| High | KMS key with deletion window < 7 days (accidental deletion risk) | AEGIS-AWS-561 |
| Medium | KMS grant with overly permissive operations | AEGIS-AWS-562 |
| Medium | Secrets Manager secret without KMS CMK (uses default aws/secretsmanager key) | AEGIS-AWS-563 |

**Coverage score: 8/10** — deep secrets detection (534–539) with taint tracking
is a differentiator. KMS grant analysis is the main gap.

---

## 5. Compute and Serverless

| Sub-area | Rules | Resource types |
|----------|-------|----------------|
| EC2 / IMDS | 204 (High), 411 (High), 541 (High) | aws_instance, aws_launch_template, aws_launch_configuration |
| EBS | 009 (Medium), 301 (High), 391 (Medium) | aws_ebs_volume, aws_launch_template |
| ECS | 302 (High), 381 (High), 382 (Medium), 383 (Medium), 412 (High), 527 (Medium) | aws_ecs_task_definition, aws_ecs_service, aws_ecs_cluster |
| EKS | 304 (High), 305 (High), 306 (Medium), 413 (Medium) | aws_eks_cluster, aws_eks_node_group |
| Lambda | 307 (High), 308 (Medium), 406 (High), 407 (High), 410 (High), 542 (Medium), 547 (Low), 548 (Low) | aws_lambda_function |
| ECR | 303 (Medium), 408 (High), 515 (Medium), 521 (Medium) | aws_ecr_repository |
| SageMaker | 366 (High), 367 (Medium), 370 (Medium), 427 (Medium), 511 (Medium), 525 (Medium), 532 (Medium) | aws_sagemaker_notebook_instance, aws_sagemaker_domain, aws_sagemaker_endpoint_configuration |
| Batch / legacy | 309 (Medium), 310 (Medium) | aws_launch_configuration |
| App Runner / Beanstalk | 394 (Medium), 395 (Medium) | (beanstalk, apprunner) |
| WorkSpaces / AppStream | 424 (High), 437 (Medium) | aws_workspaces_workspace |

**Threats covered:** IMDSv1, unencrypted volumes, privileged containers, host
networking, public EKS endpoints, Lambda env var encryption, Lambda public
invoke permissions, ECR public policies, mutable image tags, SageMaker internet
access, deprecated launch configs.

**Gaps:**
| Priority | Gap | Suggested ID |
|----------|-----|--------------|
| Medium | ECS task with `readonlyRootFilesystem` absent on Fargate (have 527 for EC2 launch type) | — (covered by 527) |
| Medium | Lambda with `reserved_concurrent_executions = -1` (unlimited, cost risk) | AEGIS-AWS-564 |
| Low | EC2 instance with `ebs_optimized` disabled on supported types | AEGIS-AWS-565 |

**Coverage score: 8/10** — broad compute coverage. Minor gaps only.

---

## 6. Databases

| Sub-area | Rules | Resource types |
|----------|-------|----------------|
| RDS instances | 007 (High), 008 (Medium), 011 (High), 207 (Medium), 311 (Medium), 446 (Medium), 540 (High), 543 (Low), 544 (Low), 546 (Low), 605 (Low), 607 (Low), 608 (Low) | aws_db_instance |
| Aurora / RDS clusters | 322 (Medium), 358 (Medium), 359 (High), 360 (Medium) | aws_rds_cluster, aws_db_cluster |
| DynamoDB | 312 (Medium), 313 (High), 417 (Medium) | aws_dynamodb_table |
| Redshift | 314 (High), 315 (High), 316 (Medium), 431 (High), 432 (Medium), 508 (High), 524 (Medium), 528 (Low), 621 (Low) | aws_redshift_cluster, aws_redshiftserverless_workgroup, aws_redshiftserverless_namespace |
| ElastiCache | 208 (Medium), 320 (Medium), 321 (Medium), 514 (High), 549 (High), 550 (High), 551 (Low) | aws_elasticache_replication_group |
| Neptune | 352 (High), 429 (Medium), 440 (Medium), 522 (Medium), 611 (Low), 612 (Low) | aws_neptune_cluster |
| DocumentDB | 351 (High), 353 (Medium), 430 (Medium), 624 (Low), 626 (Low) | aws_docdb_cluster |
| OpenSearch / ES | 318 (High), 319 (High), 418 (Medium), 507 (High), 519 (Medium), 523 (Medium), 618 (Low), 623 (Low) | aws_opensearch_domain, aws_elasticsearch_domain |
| MemoryDB / DAX | 354 (High), 355 (Medium), 439 (Medium), 518 (Medium) | aws_memorydb_cluster, aws_dax_cluster |
| DMS | 356 (High), 357 (High) | (dms resources) |
| RDS Proxy | 436 (High) | (rds proxy) |

**Threats covered:** Unencrypted storage, public accessibility, missing backups,
no deletion protection, no Multi-AZ, missing IAM auth, weak TLS, no auth tokens,
public DMS instances, unencrypted clusters across all engines.

**Gaps:**
| Priority | Gap | Suggested ID |
|----------|-----|--------------|
| Medium | RDS Performance Insights without KMS (uses default key) | AEGIS-AWS-566 |
| Low | DynamoDB table without TTL on session data (application-level, hard to detect) | — (not reliably Terraform-provable) |

**Coverage score: 10/10** — most complete database coverage of any IaC scanner.
All major engines (RDS, Aurora, DynamoDB, Redshift, ElastiCache, Neptune,
DocumentDB, OpenSearch, MemoryDB) covered for encryption, exposure, and auth.

---

## 7. Logging and Detection

| Sub-area | Rules | Resource types |
|----------|-------|----------------|
| CloudTrail | 010 (Medium), 336 (High), 340 (Medium) | aws_cloudtrail |
| Config | 393 (Medium) | aws_config_configuration_recorder |
| GuardDuty | 348 (Medium) | (guardduty detector) |
| VPC flow logs | 209 (Medium) | aws_vpc |
| Service logging (hygiene) | 327, 332, 371, 376, 377, 380, 609, 610, 613, 614, 615, 618, 620, 621, 622, 623, 625 (all Low) | various |

**Threats covered:** CloudTrail without validation, single-region trails,
missing global events, Config not recording all resources, GuardDuty disabled,
VPC without flow logs, per-service audit logging gaps.

**Gaps:**
| Priority | Gap | Suggested ID |
|----------|-----|--------------|
| High | Security Hub not enabled (centralized finding aggregation) | AEGIS-AWS-567 |
| Medium | CloudTrail without KMS encryption (have 010 for validation; gap is `kms_key_id` absent) | AEGIS-AWS-568 |
| Medium | Detective not enabled (investigation capability) | AEGIS-AWS-569 |
| Low | CloudTrail S3 bucket without MFA delete | AEGIS-AWS-570 |

**Coverage score: 7/10** — core logging covered. Security Hub / Detective are
notable gaps (centralized detection controls).

---

## 8. Supply Chain and Deployment

| Sub-area | Rules | Resource types |
|----------|-------|----------------|
| CI/CD | 384 (Medium), 385 (High), 386 (Medium), 409 (High) | aws_codebuild_project, aws_codepipeline |
| Messaging | 341 (High), 342 (High), 343 (High), 344 (High), 345 (High), 346 (Medium), 349 (Medium), 426 (High) | aws_sns_topic, aws_sqs_queue, aws_msk_cluster, aws_mq_broker |
| Kinesis | 350 (High), 365 (Medium) | (kinesis resources) |
| EventBridge / SFN | 375 (High), 376 (Medium), 377 (Medium) | (eventbridge, sfn) |
| IoT | 390 (High) | (iot policy) |
| Backup | 392 (Medium) | (backup vault) |
| Glue / Athena / Timestream | 363 (High), 364 (High), 434 (Medium), 435 (Medium), 419 (Medium) | aws_athena_workgroup, aws_glue, aws_timestreamwrite_database |
| FSx / EFS | 317 (High), 368 (High), 369 (High), 415 (High), 416 (High) | (fsx, efs) |
| Dedicated supply-chain pack | SC-001 through SC-009 (separate pack) | terraform_data, provisioners, user_data |

**Threats covered:** Unencrypted messaging queues/topics, public SNS/SQS
policies, plaintext SNS subscriptions, CodeBuild privileged mode, unauthenticated
webhooks, overly broad IoT policies, unencrypted analytics pipelines.

**Gaps:**
| Priority | Gap | Suggested ID |
|----------|-----|--------------|
| Medium | CodeArtifact repository without upstream restrictions | AEGIS-AWS-571 |
| Low | Systems Manager documents with overly permissive sharing | AEGIS-AWS-572 |

**Coverage score: 7/10** — messaging and CI/CD well covered. Dedicated
supply-chain pack (SC-001–009) handles Terraform-level threats.

---

## Summary Scores

| Category | Score | Rules | Top gap |
|----------|------:|------:|---------|
| IAM and privilege escalation | 8/10 | 17 | Access key rotation (552) |
| Networking | 9/10 | 34 | Transit Gateway routing (556) |
| S3 and data protection | 9/10 | 14 | Object Lock (558) |
| KMS and secrets | 8/10 | 13 | KMS deletion window (561) |
| Compute and serverless | 8/10 | 39 | Lambda concurrency (564) |
| Databases | 10/10 | 54 | — (complete) |
| Logging and detection | 7/10 | 24 | Security Hub (567) |
| Supply chain and deployment | 7/10 | 22 | CodeArtifact (571) |
| **Overall** | **8.25/10** | **245** | |

## Top 20 Gap Priority List (AEGIS-AWS-552+)

Ranked by (severity × prevalence × exploitability):

| # | ID | Rule | Severity | Category |
|---|----|------|----------|----------|
| 1 | 552 | IAM user access keys older than 90 days | High | IAM |
| 2 | 553 | IAM policy with NotAction+Allow (deny bypass) | High | IAM |
| 3 | 556 | Transit Gateway permissive route propagation | High | Networking |
| 4 | 558 | S3 bucket without Object Lock | Medium | S3 |
| 5 | 561 | KMS key deletion window < 7 days | High | KMS |
| 6 | 562 | KMS grant overly permissive | Medium | KMS |
| 7 | 563 | Secrets Manager without CMK | Medium | KMS |
| 8 | 564 | Lambda unlimited concurrency (cost risk) | Medium | Compute |
| 9 | 566 | RDS Performance Insights without KMS | Medium | Databases |
| 10 | 567 | Security Hub not enabled | High | Logging |
| 11 | 568 | CloudTrail without KMS encryption | Medium | Logging |
| 12 | 569 | Detective not enabled | Medium | Logging |
| 13 | 570 | CloudTrail bucket without MFA delete | Low | Logging |
| 14 | 554 | IAM role session duration > 12h | Medium | IAM |
| 15 | 555 | IAM group with inline admin policy | Medium | IAM |
| 16 | 557 | VPC endpoint policy allows * principal | Medium | Networking |
| 17 | 559 | S3 bucket without inventory | Low | S3 |
| 18 | 560 | S3 bucket with force_destroy=true | Low | S3 |
| 19 | 565 | EC2 ebs_optimized disabled | Low | Compute |
| 20 | 571 | CodeArtifact without upstream restrictions | Medium | Supply chain |

## Honest Limitations

Services with **zero or minimal** Terraform-provable coverage:
- **Direct Connect / VPN** — rarely in Terraform, low value
- **Route53** — DNS misconfigurations are hard to prove statically
- **CloudFormation StackSets** — meta-resource, limited value
- **Service Catalog** — rarely security-relevant in IaC
- **IAM MFA devices** — requires AWS API, not Terraform-provable

These are intentionally deprioritized: static IaC scanning cannot reliably
assess them, and adding speculative rules would increase false positives.
