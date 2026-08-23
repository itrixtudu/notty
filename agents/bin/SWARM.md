

Coordinator / spec arbiter      gpt-5.4
Main porter / writer            gpt-5.3-codex
Bounded patch worker            gpt-5.2-codex
Tester / regression worker      gpt-5.1-codex-mini
QA / behavior gate              gpt-5.4
Scout / archaeology helper      gpt-5.3-codex-spark   (optional, read-only)
Escalation seat                 gpt-5.1-codex-max     (optional)

## Net recommendation

For **Iniquity TP7 → C**, the best inter-agent layout is:

* **Planner:** `gpt-5.4`
* **QA:** `gpt-5.4`
* **Main porter:** `gpt-5.3-codex`
* **Mid-range patcher:** `gpt-5.2-codex`
* **Tester:** `gpt-5.1-codex-mini`
* **Scout:** `gpt-5.3-codex-spark`
* **Escalation:** `gpt-5.1-codex-max`

Minimal 3-seat version:

* `gpt-5.4` coordinator/QA
* `gpt-5.3-codex` writer
* `gpt-5.1-codex-mini` tester

For this repo, that minimal version is probably the highest signal-to-chaos ratio.



Yes. For the **Iniquity TP7 → C rebuild**, I’d bias toward a **spec-first porting cell** rather than a generic coding swarm. Your repo is explicitly split between the active C17 port (`INIQUICY/`) and the legacy/reference side (`INIQUITY/`, `TPSRC/`, `IQ2/`), and the coordination contract uses **authoritative file locks**, **one lock per agent**, and a **single coordinator declaration** for parallel work. OpenAI’s current multi-agent guidance also says parallel agents work best for **read-heavy** exploration, tests, triage, and summarization, while concurrent **write-heavy** workflows need more caution because conflict overhead rises fast.  ([OpenAI Developers][1])

## Best layout for this project

### 1) Planner / spec arbiter — **`gpt-5.4`**

Use this as the top coordinator. It is the recommended default for most Codex work and combines strong coding with stronger reasoning and broader workflow handling than the older alternatives. For a TP7 port, this seat should own decomposition, behavior contracts, lock sequencing, and final acceptance. ([OpenAI Developers][2])

### 2) Main porter / long-horizon writer — **`gpt-5.3-codex`**

This should be the main implementation seat. Official guidance positions `gpt-5.3-codex` as the most capable agentic coding model to date, and the multi-agent guidance specifically says it fits agents that do multi-step implementation, code review, or ambiguous engineering work. That maps well to Pascal-to-C semantic translation. ([OpenAI Developers][3])

### 3) Mid-range bounded patcher — **`gpt-5.2-codex`**

Use this for smaller, bounded follow-up tickets: header cleanup, parser edge cases, fixture plumbing, menu/text compatibility tweaks, or isolated refactors after the main porter has clarified semantics. OpenAI describes it as an advanced coding model for real-world engineering and long-horizon agentic tasks, though it has been succeeded by `gpt-5.3-codex`. ([OpenAI Developers][2])

### 4) Tester / fixture / regression worker — **`gpt-5.1-codex-mini`**

Use this for repetitive work: test scaffolds, fixture expansion, log triage, regression sweeps, and “did we preserve behavior?” loops. It is the smaller, more cost-effective, less-capable Codex variant, which is exactly what you want for high-volume verification rather than architecture ownership. ([OpenAI Developers][3])

### 5) QA / behavior-diff gate — **`gpt-5.4`**

Keep final QA on `gpt-5.4`. In this project, QA is not style review; it is **semantic equivalence review** against TPSRC/reference behavior, menu/text compatibility, stateful BBS behavior, and regression risk. The strongest reasoning seat belongs here.  ([OpenAI Developers][4])

## Optional sidecars

### Fast scout / archaeology helper — **`gpt-5.3-codex-spark`**

Use Spark as a **read-only scout**. Official guidance says Spark is optimized for near-instant iteration and works well for parallel workers focused on exploration, read-heavy scans, and quick summarization. For this repo, that means: trace Pascal call paths, locate corresponding C targets, summarize IQ2 fixtures, and return distilled notes to the coordinator. Do **not** let Spark own semantic decisions. ([OpenAI Developers][5])

### Deep-stamina escalation — **`gpt-5.1-codex-max`**

Reserve this for ugly, long-running tickets: porting a tangled subsystem, untangling stateful runtime behavior, or handling a branch that needs long continuity more than top-end current intelligence. It is explicitly positioned for long-horizon, agentic coding tasks. ([OpenAI Developers][2])

### General `gpt-5.2`

I would **not** give `gpt-5.2` a permanent seat here. It is still strong for disciplined production-agent behavior, but it has been succeeded by `gpt-5.4`; I’d keep it as a backup reader/spec-cleanup seat rather than core topology. ([OpenAI Developers][2])

---

## What I would actually run

```text
Coordinator / spec arbiter      gpt-5.4
Main porter / writer            gpt-5.3-codex
Bounded patch worker            gpt-5.2-codex
Tester / regression worker      gpt-5.1-codex-mini
QA / behavior gate              gpt-5.4
Scout / archaeology helper      gpt-5.3-codex-spark   (optional, read-only)
Escalation seat                 gpt-5.1-codex-max     (optional)
```

## Concurrency rule for **this** repo

Default to **one writer**. Add read-only helpers freely; add a second writer only when the tickets are clearly disjoint. Your contract allows only one file lock per agent, requires re-verification before writes, and requires a single coordinator for parallel activation. Combined with the TP7→C port shape—where one behavior slice often touches Pascal reference, C source, headers, and tests—most value comes from parallel **analysis** and **verification**, not parallel patching.  ([OpenAI Developers][1])

A good default live layout is:

* **1 coordinator**
* **1 writer**
* **1 tester**
* **1 optional read-only scout**

That is usually the sweet spot.

## Ticket granularity

For this project, the work unit should be **one behavior slice**, not “one big subsystem.” The repo itself emphasizes preserving BBS/runtime behavior, menu/text compatibility, and the TP source as reference input, with current focus around local login and related call-hooker/runtime behavior. Good ticket examples are:

* local login branch
* config parsing branch
* menu dispatch path
* text asset rendering rule
* one Pascal unit/function family at a time

That keeps the port deterministic and reduces invented semantics. 

A good handoff envelope:

```yaml
ticket_id:
pascal_refs:
c_targets:
iq2_fixtures:
behavior_contract:
allowed_files:
test_cmds:
stop_conditions:
handoff_to:
```

## Messaging plane

Your `collab.cjs` already gives you enough bus surface for this: `send/watch/mirror/tail/join/who/channels/irc/mcp`. I’d use it as a **status and evidence bus**, not as a design-negotiation layer. Coordinator assigns; workers report; QA gates. 

[1]: https://developers.openai.com/codex/llms-full.txt?utm_source=chatgpt.com "llms-full.txt"
[2]: https://developers.openai.com/codex/models/ "Codex Models"
[3]: https://developers.openai.com/api/docs/models/all "All models | OpenAI API"
[4]: https://developers.openai.com/codex/cli/features/ "Codex CLI features"
[5]: https://developers.openai.com/codex/models/?utm_source=chatgpt.com "Codex Models"

