# Current work

> Completed items are archived monthly in `tasks/history/`; the ship log stays in `tasks/history.md`.

## Needs George (todo audit 2026-11-05)

- Milestone 12's three open items (v1 parity harness, SQLite-to-Durable-Object importer, staging deploy/cutover) have no related commits since the 2026-08-16 foundation; work since then went to protected computer use and the agent broker. Still the current plan and order?
- This todo has no entries for work merged since August (PRs #48 Brave protected fill, #51 agent secret broker, #52 agent setup; tasks/protected-computer-use-2026-11-03.md). Should those be recorded here, or are they tracked elsewhere?

## Milestone 12: Cloudflare-first migration — foundation complete

- [ ] Complete the cross-language v1 parity harness and close every Worker
  route, error, audit, pagination, concurrency, and schema-migration gap before
  any production data or hostname is placed on the Worker.
- [ ] Build the authenticated resumable SQLite-to-Durable-Object importer with
  per-vault transactional import and identifier/ciphertext-free count and
  digest comparison.
- [ ] Deploy marked staging resources, run the full migration and restore
  journeys, complete the maintenance-window cutover and seven-day observation,
  then retire the legacy Go/Docker/Railway production paths.

## Milestone 11: $0 end-to-end execution — implementation complete

- [ ] Execute the explicitly authorized Stripe, Clerk Development, and
  Cloudflare observations against dedicated marked resources before the next
  release.

Later milestones are tracked in the [product roadmap](../docs/roadmap.md).

## Blockers

- SiftCut Cloud implementation belongs to the separate `short-editor`
  repository, which is outside this workspace's writable scope. Its D1/R2/
  Queues/Workers AI/Containers refactor and PostgreSQL-to-D1 importer remain
  unimplemented here.
