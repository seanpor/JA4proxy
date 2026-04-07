# JA4proxy Elastic Stack Integration

## Overview

This integration ships JA4proxy telemetry to Elasticsearch 8.x with:
- ECS 8.x compliant index template with JA4proxy extension field mappings
- ILM policy (hot 7d/50GB → warm 30d → cold 90d → delete)
- Ingest pipeline with GeoIP enrichment on `source.ip`
- Vector shipping agent configuration

## Requirements

- Elasticsearch 8.x and Kibana 8.x (self-managed or Elastic Cloud)
- GeoLite2-City and GeoLite2-ASN Elasticsearch ingest plugins (for GeoIP)
- JA4proxy with `logging.format: ecs` in `config/proxy.yml`
- Vector shipping agent on the JA4proxy host

## Setup Steps

### Step 1: Apply the ILM Policy

```bash
curl -X PUT "${ELASTIC_URL}/_ilm/policy/ja4proxy-ilm-policy" \
  -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @integrations/elastic/ilm-policy.json
```

### Step 2: Create the Ingest Pipeline

```bash
curl -X PUT "${ELASTIC_URL}/_ingest/pipeline/ja4proxy-enrichment" \
  -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @integrations/elastic/ingest-pipeline.json
```

Verify the pipeline was created:
```bash
curl -s "${ELASTIC_URL}/_ingest/pipeline/ja4proxy-enrichment" \
  -H "Authorization: ApiKey ${ELASTIC_API_KEY}" | jq .
```

### Step 3: Apply the Index Template

```bash
curl -X PUT "${ELASTIC_URL}/_index_template/ja4proxy" \
  -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @integrations/elastic/index-template.json
```

Verify with:
```bash
curl -s "${ELASTIC_URL}/_index_template/ja4proxy" \
  -H "Authorization: ApiKey ${ELASTIC_API_KEY}" | jq '.index_templates[0].index_template.template.settings'
```

### Step 4: Configure the Vector Shipping Agent

On the JA4proxy host:

```bash
export ELASTIC_URL=https://your-cluster.es.region.aws.elastic-cloud.com
export ELASTIC_API_KEY=your-base64-api-key

python3 proxy.py 2>&1 | vector --config config/integrations/vector-elastic.yaml
```

### Step 5: Verify Data Ingestion

```bash
# Check that the index was created
curl -s "${ELASTIC_URL}/_cat/indices/ja4proxy-*?v" \
  -H "Authorization: ApiKey ${ELASTIC_API_KEY}"

# Sample a few events
curl -s "${ELASTIC_URL}/ja4proxy-*/_search" \
  -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"size": 3, "sort": [{"@timestamp": "desc"}]}' | jq '.hits.hits[]._source | {timestamp: .["@timestamp"], action: .["event.action"], score: .["event.risk_score"], src: .["source.ip"]}'
```

## Index Template Details

The template covers `ja4proxy-*` indices and defines:

| Field | Elasticsearch Type | Notes |
|---|---|---|
| `@timestamp` | date | Required; set by JA4proxy |
| `source.ip` | ip | Enables CIDR range queries |
| `source.port` | integer | |
| `destination.ip` | ip | |
| `event.action` | keyword | Indexed for aggregations |
| `event.risk_score` | float | Enables range aggregations |
| `tls.version` | keyword | |
| `ja4proxy.fingerprint.ja4` | keyword | Fingerprint analytics |
| `ja4proxy.fingerprint.ja4x` | keyword | |
| `ja4proxy.fingerprint.ja4t` | keyword | |
| `ja4proxy.signals` | nested | Preserves signal array structure |
| `ja4proxy.score` | float | Alias for event.risk_score |
| `ja4proxy.dial_setting` | integer | |
| `source.geo.*` | geo_point / keyword | Added by ingest pipeline |

## ILM Policy Summary

| Phase | Age / Size Trigger | Action |
|---|---|---|
| Hot | 0–7 days or 50 GB | Active writes, 1 shard, 1 replica |
| Warm | 7–30 days | Shrink to 1 shard, read-only |
| Cold | 30–90 days | 0 replicas, frozen |
| Delete | After 90 days | Index deleted |

Adjust `min_age` values in `ilm-policy.json` to meet your retention requirements.

## GeoIP Enrichment

The ingest pipeline calls the `geoip` processor using Elasticsearch's built-in
MaxMind GeoLite2 databases. After enrichment, events contain:

```json
"source": {
  "ip": "198.51.100.4",
  "geo": {
    "country_iso_code": "US",
    "country_name": "United States",
    "city_name": "New York",
    "location": { "lat": 40.7128, "lon": -74.0060 }
  },
  "as": {
    "asn": 14061,
    "organization_name": "DIGITALOCEAN-ASN"
  }
}
```

This enables Kibana Maps to display blocked IPs geographically.

## API Key Permissions

Create an API key with write access to `ja4proxy-*`:

```json
{
  "name": "ja4proxy-vector-writer",
  "role_descriptors": {
    "ja4proxy_writer": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": ["ja4proxy-*"],
          "privileges": ["create_index", "index", "write", "view_index_metadata"]
        }
      ]
    }
  }
}
```

```bash
curl -X POST "${ELASTIC_URL}/_security/api_key" \
  -H "Authorization: Basic $(echo -n 'elastic:PASSWORD' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"name": "ja4proxy-vector-writer", "role_descriptors": {"ja4proxy_writer": {"cluster": ["monitor"], "indices": [{"names": ["ja4proxy-*"], "privileges": ["create_index", "index", "write", "view_index_metadata"]}]}}}'
```

## Kibana Security Integration

JA4proxy events follow ECS 8.x, so they are compatible with the Kibana Security
solution out of the box:

1. In Kibana, go to **Security → Overview** — JA4proxy events appear in the
   Network Events section.
2. Create a data view for `ja4proxy-*` in **Stack Management → Data Views**.
3. Use **Discover** with the JA4proxy data view for ad-hoc investigation.

## Troubleshooting

**Pipeline errors:** Check for events tagged with `_pipeline_error`:
```
GET /ja4proxy-*/_search
{ "query": { "exists": { "field": "_pipeline_error" } }, "size": 5 }
```

**GeoIP not enriching:** Install the GeoLite2 databases in Elasticsearch:
```bash
# Enable automatic database updates
PUT /_cluster/settings
{ "persistent": { "ingest.geoip.downloader.enabled": true } }
```

**ILM policy not advancing:** Check with:
```bash
GET /ja4proxy-*/_ilm/explain
```
