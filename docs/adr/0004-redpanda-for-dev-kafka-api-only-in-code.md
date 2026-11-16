# ADR-0004: Redpanda for dev, Kafka API only in code

- Status: accepted
- Date: 2026-11-16
- Decision ID: D4 (docs/10-decisions-for-approval.md)

## Context
An event bus is needed from P2. RAM is limited. Redpanda Community is BSL 1.1.

## Decision
Run Redpanda single-node in dev. Code depends only on the Kafka protocol and clients, so Apache Kafka (KRaft) is a drop-in.

## Alternatives considered
Apache Kafka from day one.

## Consequences
Revisit before any commercial distribution (risk R9).
