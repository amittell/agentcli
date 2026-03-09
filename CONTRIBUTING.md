# Contributing

## Scope

Contributions should strengthen one of these areas:

- manifest stability
- target adapters
- schema and describe surfaces
- JSON-RPC
- documentation and conformance

## Ground Rules

- keep the manifest backend-portable unless a change is explicitly target-specific
- do not move durable runtime behavior into this repo
- prefer additive changes over semantic rewrites
- update tests when changing validation, compile behavior, or protocol behavior
- update the relevant spec docs when changing public contracts

## Development

```bash
npm test
```

## Before Opening a PR

- explain whether the change affects the manifest spec, package implementation, or both
- call out any compatibility risk
- include example input and output when changing compile or protocol behavior
