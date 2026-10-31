# Elastic / ECS integration

`export-ecs` produces one JSON alert per line using ECS field names and allowed
values. Configure an existing Filebeat/Elastic Agent pipeline to ingest that file.
`event.outcome` is `failure` only for an explicitly failed source record; otherwise
it is `unknown`. Alerts are not native Kibana detection-engine alert documents.

```yaml
# Example Filebeat input. Replace path for your controlled environment.
filebeat.inputs:
  - type: filestream
    id: postgres-audit-guard
    paths: ["/path/to/alerts.ndjson"]
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
```

Use your existing authenticated/TLS-protected output configuration. This project
does not manage credentials or provision an Elasticsearch cluster. Use `event.id`
as an idempotent document identifier when appropriate; it derives from source
bytes and rule ID. Two identical captured records generate the same identifier.
Filter `event.dataset:postgres_audit_guard.postgresql` and inspect `rule.id` plus
`postgres_audit_guard.severity`. Source bytes are excluded: use `event.hash` to locate
the authorized investigator's sealed evidence.

The exporter and fields are tested locally. An Elasticsearch/Filebeat deployment
has **not** been executed as part of the published first milestone. This is an
integration format and configuration example, not vendor certification.

References: [ECS event fields](https://www.elastic.co/docs/reference/ecs/ecs-event),
[rule fields](https://www.elastic.co/docs/reference/ecs/ecs-rule),
[Elastic Security field reference](https://www.elastic.co/docs/reference/security/fields-and-object-schemas/siem-field-reference).
