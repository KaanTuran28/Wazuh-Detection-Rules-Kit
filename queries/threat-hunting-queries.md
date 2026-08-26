# Threat-Hunting Queries

Documented OpenSearch/Elasticsearch Query DSL snippets for hunting inside the `wazuh-alerts-*` index (Wazuh's default alert index pattern). Run these from the Wazuh dashboard's Discover/Dev Tools view, or via the OpenSearch `_search` API.

## 1. Spike in high-severity alerts for a single agent

Hunts for an agent suddenly producing many critical (level >= 12) alerts in a short window — a common sign of active exploitation or a brute-force success.

```json
{
  "query": {
    "bool": {
      "filter": [
        { "range": { "rule.level": { "gte": 12 } } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "aggs": {
    "by_agent": { "terms": { "field": "agent.name", "size": 20 } }
  }
}
```

## 2. Single source IP failing auth as many distinct usernames

Hunts for password-spraying: one IP trying many different accounts in a short window.

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "rule.groups": "authentication_failed" } },
        { "range": { "@timestamp": { "gte": "now-15m" } } }
      ]
    }
  },
  "aggs": {
    "by_source_ip": {
      "terms": { "field": "data.srcip", "size": 50 },
      "aggs": {
        "distinct_users": { "cardinality": { "field": "data.dstuser" } }
      }
    }
  }
}
```
Flag any `srcip` bucket where `distinct_users` >= 5.

## 3. Administrative logins outside business hours

Hunts for privileged authentication events occurring outside the 08:00–19:00 local window.

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "rule.groups": "authentication_success" } },
        { "terms": { "data.dstuser": ["admin", "root", "administrator"] } }
      ],
      "must_not": [
        { "script": { "script": "doc['@timestamp'].value.getHour() >= 8 && doc['@timestamp'].value.getHour() < 19" } }
      ]
    }
  }
}
```

## 4. First-time-seen process command line (rarity hunt)

Hunts for a `data.win.eventdata.commandLine` value that has not appeared in the last 30 days — useful for spotting novel living-off-the-land tooling.

```json
{
  "size": 0,
  "query": { "range": { "@timestamp": { "gte": "now-30d" } } },
  "aggs": {
    "rare_command_lines": {
      "rare_terms": {
        "field": "data.win.eventdata.commandLine",
        "max_doc_count": 1
      }
    }
  }
}
```

## 5. New geography for a known user

Hunts for a successful authentication from a GeoIP country not seen for that user in the trailing 90 days. Requires a GeoIP-enriched field such as `GeoLocation.country_name`.

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "rule.groups": "authentication_success" } },
        { "term": { "data.dstuser": "kaan" } },
        { "range": { "@timestamp": { "gte": "now-1d" } } }
      ]
    }
  },
  "aggs": {
    "countries_seen_today": { "terms": { "field": "GeoLocation.country_name" } }
  }
}
```
Compare the resulting country set against the trailing-90-day baseline for the same user; anything new is worth reviewing.

## 6. Rare parent-child process pairs

Hunts for unusual process lineage (e.g. `winword.exe` spawning `powershell.exe`), a classic macro-malware / phishing execution chain.

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [{ "range": { "@timestamp": { "gte": "now-7d" } } }]
    }
  },
  "aggs": {
    "pairs": {
      "composite": {
        "sources": [
          { "parent": { "terms": { "field": "data.win.eventdata.parentImage" } } },
          { "child": { "terms": { "field": "data.win.eventdata.image" } } }
        ]
      }
    }
  }
}
```
Sort results ascending by `doc_count` and review the least common pairs first.

## 7. Web attack rule bursts per source IP

Hunts for a single source IP repeatedly triggering the custom web-attack rules (100020-100022) in this kit within a short window — likely automated scanning/fuzzing.

```json
{
  "query": {
    "bool": {
      "filter": [
        { "terms": { "rule.id": ["100020", "100021", "100022"] } },
        { "range": { "@timestamp": { "gte": "now-10m" } } }
      ]
    }
  },
  "aggs": {
    "by_source_ip": { "terms": { "field": "data.srcip", "size": 20 } }
  }
}
```

## 8. Multiple distinct hosts triggering the same host-anomaly rule

Hunts for the same anomaly (e.g. rule 100030 - obfuscated PowerShell) firing across several hosts in a short window, suggesting a coordinated campaign rather than an isolated incident.

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "rule.id": "100030" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "aggs": {
    "distinct_agents": { "cardinality": { "field": "agent.name" } },
    "by_agent": { "terms": { "field": "agent.name", "size": 20 } }
  }
}
```
