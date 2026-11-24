# Documentation

This directory holds the technical documentation for Python SOC Automation Engine. For an overview, installation steps, and basic usage, start with the [root README](../README.md).

## Documents

| Document | Description |
|---|---|
| [Architecture](architecture.md) | Design principles, processing flow for normal processing and batch triage, module responsibilities, enrichment, investigation output, and scope boundaries. |
| [Integration Contract](integration-contract.md) | The reference for the normal-processing output schema (version `1.2`) and the CLI interface: accepted input, field definitions, nullability, enrichment and investigation structure, warnings and errors, and compatibility guidance. |
| [Testing Strategy](testing.md) | How the automated test suite is organized and run, what each test module covers, and the limitations of the testing. |
| [Sample Output](sample-output.md) | Example output for the engine's workflows. The examples are illustrative, not captured execution results. |
| [Development Log](development-log.md) | Record of the project's development history. |

## Where to start

| If you want to... | Read |
|---|---|
| Understand how the engine is structured and what it does and does not do | [Architecture](architecture.md) |
| Consume the engine's output or integrate with its CLI | [Integration Contract](integration-contract.md) |
| Run or understand the tests | [Testing Strategy](testing.md) |
| See what output looks like | [Sample Output](sample-output.md) |
| Follow how the project developed | [Development Log](development-log.md) |

## Notes

- **Schema and CLI reference.** The [Integration Contract](integration-contract.md) is the reference for the normal-processing schema and the CLI interface. Batch triage reports are not covered by the schema `1.2` envelope.
- **Illustrative examples.** Examples in [Sample Output](sample-output.md) show the shape of the output. They are not recorded results from a particular run, so verify behavior by running the tool.
- **Implementation status.** Each document states what is implemented and what is future work. Treat anything listed as future work as not currently available.
- **Scope.** The engine processes exported Wazuh alert files. The documentation does not describe live Wazuh integration, real-time monitoring, or autonomous response, because the engine does not provide them.
