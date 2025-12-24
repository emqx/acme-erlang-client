# ACME Client Examples

This directory contains example implementations for DNS-01 challenge responders and test infrastructure.

## Test DNS Server

The `acme_client_dns_responder.py` script is a simple DNS server used for testing DNS-01 challenges with Pebble ACME test server.

### Features

- Responds to DNS TXT record queries on port 53 (UDP/TCP)
- HTTP API on port 8053 for dynamically setting challenge records
- Used by the test suite for DNS-01 challenge validation

### Usage

```bash
python3 acme_client_dns_responder.py
```

The server will:
- Listen on UDP port 53 for DNS queries
- Listen on TCP port 8053 for HTTP API requests

### HTTP API

- `POST /set-challenge` - Set a DNS challenge record
- `DELETE /clear-challenge?domain=example.com` - Clear challenge records
- `GET /health` - Health check endpoint

## AWS Route53 DNS Challenge

The `aws_route53_dns_challenge.sh` script creates or updates TXT records in AWS Route53 for ACME DNS-01 challenges.

### Prerequisites

- AWS CLI installed and configured
- Appropriate AWS credentials (via environment variables or `~/.aws/credentials`)
- IAM permissions for Route53: `route53:ChangeResourceRecordSets` and `route53:ListHostedZones`

### Usage

```bash
./aws_route53_dns_challenge.sh <record_name> <record_value> [hosted_zone_id]
```

**Parameters:**
- `record_name`: The TXT record name (e.g., `_acme-challenge.example.com`)
- `record_value`: The challenge value (base64url-encoded SHA-256 digest)
- `hosted_zone_id`: (Optional) AWS hosted zone ID. If not provided, the script will look it up automatically.

**Environment Variables:**
- `AWS_REGION`: AWS region (default: us-east-1)
- `AWS_PROFILE`: AWS profile to use (optional)

### Example

```bash
./aws_route53_dns_challenge.sh \
  "_acme-challenge.example.com" \
  "CfryYhzPF_US6Ro9JQ17HHj55O5jzlWwK7qlVu2RKgs" \
  "Z1234567890ABCDEF"
```

### Integration with ACME Client

See `README.md` in the project root for Erlang integration example.
