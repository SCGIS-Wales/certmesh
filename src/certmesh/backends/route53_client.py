"""
certmesh.route53_client
========================

AWS Route53 DNS record management for ACM certificate validation.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from certmesh.exceptions import ACMValidationError

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]


def sync_validation_records(
    hosted_zone_id: str,
    certificate_arn: str,
    acm_cfg: JsonDict,
) -> int:
    """Create/upsert CNAME records in Route53 for ACM DNS validation.

    Returns the number of records synced.
    """
    region = acm_cfg.get("region", "us-east-1")

    # Fetch validation records from ACM
    acm = boto3.client("acm", region_name=region)
    try:
        resp = acm.describe_certificate(CertificateArn=certificate_arn)
    except ClientError as exc:
        raise ACMValidationError(
            f"Failed to describe certificate '{certificate_arn}': {exc}"
        ) from exc

    cert_detail = resp.get("Certificate", {})
    domain_validations = cert_detail.get("DomainValidationOptions", [])

    changes: list[JsonDict] = []
    for dv in domain_validations:
        rr = dv.get("ResourceRecord")
        if rr is None:
            continue
        changes.append(
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": rr["Name"],
                    "Type": rr["Type"],
                    "TTL": 300,
                    "ResourceRecords": [{"Value": rr["Value"]}],
                },
            }
        )

    if not changes:
        logger.warning(
            "No DNS validation records found", extra={"certificate_arn": certificate_arn}
        )
        return 0

    # Upsert to Route53
    r53 = boto3.client("route53")
    try:
        r53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={"Comment": "certmesh ACM DNS validation", "Changes": changes},
        )
    except ClientError as exc:
        raise ACMValidationError(
            f"Failed to sync Route53 records for zone '{hosted_zone_id}': {exc}"
        ) from exc

    logger.info(
        "Synced DNS validation records to Route53",
        extra={
            "record_count": len(changes),
            "hosted_zone_id": hosted_zone_id,
            "certificate_arn": certificate_arn,
        },
    )
    return len(changes)


def delete_validation_records(
    hosted_zone_id: str,
    records: list[JsonDict],
    region: str = "us-east-1",
) -> int:
    """Delete CNAME validation records from Route53 after certificate issuance.

    Returns the number of records deleted.
    """
    if not records:
        return 0

    changes: list[JsonDict] = []
    for rr in records:
        changes.append(
            {
                "Action": "DELETE",
                "ResourceRecordSet": {
                    "Name": rr["Name"],
                    "Type": rr["Type"],
                    "TTL": 300,
                    "ResourceRecords": [{"Value": rr["Value"]}],
                },
            }
        )

    r53 = boto3.client("route53")
    try:
        r53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={"Comment": "certmesh cleanup", "Changes": changes},
        )
    except ClientError as exc:
        raise ACMValidationError(
            f"Failed to delete Route53 records from zone '{hosted_zone_id}': {exc}"
        ) from exc

    logger.info(
        "Deleted DNS validation records from Route53",
        extra={"record_count": len(changes), "hosted_zone_id": hosted_zone_id},
    )
    return len(changes)
