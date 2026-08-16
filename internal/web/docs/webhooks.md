# Outbound webhooks & triggers

Boardchestrator can push events out to other systems, and fire scheduled triggers that run agent work.

## Webhooks

An org-level **webhook** receives event notifications as HTTP POSTs to a URL you configure.

- Create one under **Webhooks** in the org.
- Set the **event filter** (comma-separated) to choose which events you care about — e.g. `task.create, task.update`.
- Provide a **secret**; the delivery signs the payload so a receiver can verify it came from Boardchestrator.
- **Disable** a webhook without deleting it to pause delivery; the delivery log keeps a record of attempts and failures.

## Triggers

A **trigger** fires on a schedule (or on an event) to run agent work — for example, "every morning, triage unassigned tasks". Configure the schedule and the agent prompt in the project's **Triggers** page.
