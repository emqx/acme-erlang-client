#!/bin/bash
#
# AWS Route53 DNS-01 Challenge Script
#
# This script creates or updates a TXT record in AWS Route53 for ACME DNS-01 challenges.
#
# Usage:
#   ./aws_route53_dns_challenge.sh <record_name> <record_value> [hosted_zone_id]
#
# Environment variables:
#   AWS_REGION - AWS region (default: us-east-1)
#   AWS_PROFILE - AWS profile to use (optional)
#
# Example:
#   ./aws_route53_dns_challenge.sh "_acme-challenge.example.com" "abc123..." "Z1234567890"
#

set -euo pipefail

RECORD_NAME="${1:-}"
RECORD_VALUE="${2:-}"
ZONE_ID="${3:-}"

if [ -z "$RECORD_NAME" ] || [ -z "$RECORD_VALUE" ]; then
    echo "Usage: $0 <record_name> <record_value> [hosted_zone_id]" >&2
    exit 1
fi

# Get hosted zone ID if not provided
if [ -z "$ZONE_ID" ]; then
    # Extract base domain (e.g., "example.com" from "_acme-challenge.sub.example.com")
    BASE_DOMAIN="${RECORD_NAME#_acme-challenge.}"

    # Get hosted zone ID
    ZONE_ID=$(aws route53 list-hosted-zones-by-name \
        --dns-name "$BASE_DOMAIN" \
        --query 'HostedZones[0].Id' \
        --output text 2>/dev/null || echo "")

    if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" = "None" ]; then
        echo "Error: Could not find hosted zone for domain: $BASE_DOMAIN" >&2
        exit 1
    fi

    # Remove /hostedzone/ prefix if present
    ZONE_ID="${ZONE_ID#/hostedzone/}"
fi

# Create change batch JSON
CHANGE_BATCH=$(cat <<EOF
{
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$RECORD_NAME",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [
          {
            "Value": "\"$RECORD_VALUE\""
          }
        ]
      }
    }
  ]
}
EOF
)

# Execute the change
CHANGE_ID=$(aws route53 change-resource-record-sets \
    --hosted-zone-id "$ZONE_ID" \
    --change-batch "$CHANGE_BATCH" \
    --query 'ChangeInfo.Id' \
    --output text)

if [ $? -eq 0 ]; then
    echo "Successfully created/updated TXT record: $RECORD_NAME"
    echo "Change ID: $CHANGE_ID"
    exit 0
else
    echo "Error: Failed to create/update TXT record" >&2
    exit 1
fi
