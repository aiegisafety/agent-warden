# adapters/ — per-agent integration adapters

Adapters make an existing autonomous agent route its real-world reach through the
AW broker with as little friction as possible — ideally near-transparently. This
directly addresses the top adoption risk (the mediation install footprint). Licensed **Apache-2.0**.

**Status:** P1+. Empty until the broker interface stabilizes.

Planned adapter targets (indicative): OpenClaw, Claude Code, AutoGPT-class agents.
Each adapter's job: intercept the agent's shell / network / filesystem / credential
access and redirect it through the broker, so the agent gets no unmediated path.
