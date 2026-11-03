# Analyst workflow

This workflow applies to an authorized administrator investigating their own
PostgreSQL deployment. The included banking example is one synthetic domain;
the collection and integrity mechanisms also apply to other PostgreSQL systems.

1. Obtain a bounded copy of the server's `jsonlog` through your approved collection
   process. Record collection authority, host identity, timezone and time range in
   your existing case-management system. This tool cannot attest those facts.
2. Scan the copy into a **new private directory**. Preserve a printed manifest
   SHA-256 separately in a trusted case record. Never replace an old bundle to
   make verification pass.
3. Verify using that separately retained digest. Investigate any nonzero exit
   before relying on findings. Do not interpret an incomplete capture as complete.
4. Review the policy signal against application change records and PostgreSQL
   permissions. Sensitive-table names are explicit example policy, not automatic
   data classification. A legitimate export can trigger DB004.
5. Correlate ordinary statement records with errors, sessions and trusted database
   evidence outside this tool. An unknown outcome must stay unknown until supported.
   A successful command does not necessarily establish committed transaction state.
6. Share a minimized ECS export with your existing security pipeline. Keep raw
   SQL and captured identities in the authorized private evidence store. Source
   hashes allow later association but are not themselves anonymization.
7. Have another authorized analyst verify the sealed bundle against the trusted
   anchor. Retention, access control, deletion, custody and legal processes remain
   the operator's responsibilities.

## Transfer-case review

For an authorized transfer extract, follow the [versioned case guide](ANALYST-CASES.md).
Record the selected report/alert, reasons and references as explicit human review
assertions. An explained legitimate settlement remains in the detector report;
review status is separate from detection. Preserve prior snapshots and maintain
trusted current-head anchors and analyst authorization in your existing system.

## Next integration milestone

Run an actual controlled Filebeat/Elasticsearch ingest, validate mappings and
document identifiers, then test replay, malformed exports and duplicate handling.
Keep that integration optional; local verification should require no account or
network service. Broader cloud, application and AI-security work should retain the
same evidence-first validation approach without pretending this tool covers them.
