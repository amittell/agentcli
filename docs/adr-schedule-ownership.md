# ADR: Schedule Ownership

Date: 2026-03-28
Status: Accepted

This decision is documented in the openclaw-scheduler repository.

See: openclaw-scheduler/docs/adr-schedule-ownership.md

## Summary

- agentcli compiles durable workflow intent toward openclaw-scheduler, never toward OpenClaw native cron
- OpenClaw native cron/heartbeat is for non-durable personal assistant automation
- openclaw-scheduler is for durable manifest workflows requiring retry, approval, chaining, audit, or guaranteed delivery

## Impact on agentcli

- The `TARGETS` registry has no OpenClaw-cron target and should not gain one
- `compileManifestToScheduler` compiles `schedule.cron` into scheduler job fields only
- Triggered tasks use sentinel cron `0 0 31 2 *` to satisfy the scheduler schema; actual dispatch is trigger-based
