# Guided reviewer demonstration

The reviewer demonstration presents the existing laboratory evidence as an observable workflow. It does not add a deployment claim or change the advisory nature of the assurance outcomes.

## Starting the application

Run the dashboard without an existing evidence path.

```bash
uv run veritas-ai dashboard
```

The default run root is `runs/reviewer`. A completed run can still be opened directly.

```bash
uv run veritas-ai dashboard --run runs/trl3
```

## Guided mode

The application first checks storage, required libraries, output-path safety, and the optional Docker route. The portable route is selected by default. It generates a safe PCAP and uses deterministic Zeek-format connection records. Selecting Zeek causes the PCAP to be processed through the immutable Zeek container.

Start New Demonstration executes the real data-generation, model-training, baseline, and monitoring functions. Progress is reported after each 250 generated observations and after each evidence stage. No timed animation is used as a substitute for computation.

The first five scenarios run before the operator checkpoint. Partial telemetry loss is deliberately unlabelled, which leaves accuracy, calibration, and false-negative evidence unavailable. The model-replacement scenario produces `withdraw` after the observed model hash fails the baseline integrity check.

The reviewer must acknowledge the investigation before recovery is evaluated. Two deterministic 125-observation windows are drawn from stratified baseline conditions. Both must remain inside the warning envelope. The final recovery event and its two checks are then included in the signed ledger.

## Signed evidence mode

Signed Evidence Review verifies event order, hashes, Ed25519 signatures, the terminal seal, and agreement with the run summary before it renders any result. The reviewer can inspect outcome history, PSI, missingness, label availability, CUSUM evidence, labelled measures, feature drift, latency, recovery checks, and artifact hashes.

The Safe Tamper Test changes one metric in a temporary ledger copy. The copy must fail verification while the canonical ledger hash remains unchanged.

## Limits

The demonstration uses synthetic data and a laboratory classifier. It has no external partner validation, representative operational environment, live traffic, or automatic security action. Its evidence remains consistent with TRL 3 and does not demonstrate TRL 6.
