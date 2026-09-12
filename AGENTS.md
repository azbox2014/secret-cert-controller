## AgentWiki

This repository has an agent-maintained wiki in the `agentwiki/` directory, kept in sync by the `agentwiki` CLI.

Start here:
- [Quickstart](agentwiki/quickstart.md)
- [Architecture](agentwiki/architecture.md)
- [Recent activity](agentwiki/activity.md)

How to work with it:
- Before exploring the codebase, read `agentwiki/quickstart.md` and follow its links for context. Prefer the wiki over cold exploration.
- Wiki pages mix machine-owned fact blocks (`<!-- agentwiki:facts ... -->`) with agent-owned prose slots (`<!-- agentwiki:prose ... -->`). NEVER edit fact blocks — they are regenerated deterministically by the `agentwiki` CLI.
- After completing a task, run `npx -y @julianoczkowski/agentwiki@latest queue --json`. If it lists ANY empty or stale prose slots, fill them (prioritize slots related to files you touched, but do not leave others empty): edit only the text between the prose markers, then set `status="fresh"` and `facts-hash` to the value reported by the queue for that slot.
- Keep prose slots to 1-3 tight paragraphs, grounded in code you actually inspected.
