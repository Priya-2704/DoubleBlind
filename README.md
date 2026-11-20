# DOUBLEBLIND

**Adversarial evaluation is a protocol between mutually distrusting parties, not an environment they share.**

When a red team, a blue team and the model under test run in one shared sandbox, the
evaluation leaks: payloads become visible before the test ends, defensive rules become
inferable from attacker feedback, session state carries across tenants, and timing
carries information no content filter inspects. The result is findings nobody can
falsify — a vulnerability that only reproduces in the dirty environment, or a defence
that was quietly tuned to the exact payload used to test it.

DOUBLEBLIND puts Red, Blue and the model in separate trust domains and mediates every
permitted message through one gateway that tags, scans, reduces, pads and logs it. The
output of a run is not a finding. It is a finding **plus machine-checkable evidence
about the conditions the finding was produced under.**

Python 3.12, standard library only. No third-party dependencies anywhere in the project.

---

## Run it

```bash
py -3.12 scripts/demo.py
```

Seven acts, about twenty seconds, no setup. Each act states a claim and then passes or
fails it in front of you. Nothing is staged: the leak in act 3 is produced by actually
misconfiguring the stack, the tamper in act 5 actually rewrites the log on disk, and the
two arms in act 7 are two real deployments measured under the same load.

```
ACT 1  No path from a party to the model              [PASS]
ACT 2  Blue receives four fields, and that is asserted [PASS]
ACT 3  Contamination DNA catches a real misconfiguration [PASS]
ACT 4  Shadow Replay reports a rate, not a boolean     [PASS]
ACT 5  Log edits are evident and localised             [PASS]
ACT 6  The run emits a Proof Pack                      [PASS]
ACT 7  How much of a result is the environment         [PASS]

SUMMARY   7/7 acts passed in 21.7s
```

Tests and measurements:

```bash
py -3.12 -m unittest discover -s tests          # 43 tests
py -3.12 scripts/measure_timing.py --trials 120 # regenerates artifacts/timing.json
py -3.12 scripts/measure_delta.py  --trials 30  # regenerates artifacts/delta.json
py -3.12 scripts/verify_log.py artifacts/audit.log
```

## The dashboard

```bash
py -3.12 -m doubleblind.api
```

Then open <http://127.0.0.1:8800>. Nine tabs over the same engine the demo
script drives — and **every figure on the page is read from the running
system**. The DNA tab genuinely restarts the stack into the misconfigured
deployment. The audit tab genuinely edits an entry on disk, and restores it.
The timing chart is `artifacts/timing.json`, not an illustration.

Where a control cannot be demonstrated honestly in the current deployment —
container network isolation while running in process mode, hardware
hypervisor isolation, microarchitectural channels — the page labels it
**simulated** instead of showing a number. `/api/status` is the single source
for that split, so the badge cannot drift from what the engine actually does.

The API is plain `http.server`; the front end is one dependency-free HTML
file in `web/`. No build step, no npm.

---

## The seven mechanisms

| Mechanism | What it does | Where |
|---|---|---|
| **Contamination delta** | Two-arm controlled experiment: the same workload against a clean and a shared deployment, so a property of the model can be told from a property of the environment. | `delta.py` |
| **Private sandboxes** | One model server and one session per party. No shared context store, no shared cache. | `harness.py`, `deploy/docker-compose.yml` |
| **Secure gateway** | The only path between parties. Routes, redacts, logs, pads, quarantines. | `gateway.py` |
| **Contamination DNA** | Per-session canary markers. A marker seen outside its own session names the source session and party. | `dna.py` |
| **Timing padding** | Fixed-tick release quantises observable latency. | `timing.py` |
| **Shadow Replay** | Re-runs a finding in *N* independently opened sessions; reports a rate with a Wilson interval. | `replay.py` |
| **Audit + Proof Pack** | Hash-chained log with per-entry digests and keyed checkpoints; the pack is assembled only from recorded measurements. | `audit.py`, `proofpack.py` |

---

## Measured results

These are measurements from this machine, reproducible with the command above. They are
not projections, and where they contradict our earlier estimates we kept the measurement.

### Timing padding costs more than we assumed

Two request classes differ by ~40 ms of real model compute. An observer that can time
only its own round trips tries to tell them apart. The statistic is the distinguishing
advantage — ROC AUC on latency alone, folded into [0.5, 1.0], where 0.5 is a coin flip.

| Release tick | Distinguishing advantage | Added latency |
|---|---|---|
| 0 ms (unpadded) | **1.000** | — |
| 50 ms | 0.920 | +46 ms |
| 100 ms | 0.757 | +96 ms |
| 150 ms | 0.531 | +146 ms |
| 200 ms | **0.502** | +196 ms |

*n = 80 per class per arm, interleaved; `artifacts/timing.json`.*

**Quantisation only destroys information when the tick exceeds the difference it is
hiding.** A 25 ms tick against a 40 ms gap achieves nothing at all — advantage stays at
1.000. Reaching indistinguishability costs roughly 4× the separation in added latency.
Our pitch deck estimated this as 1.00 → 0.42 for +5.9 ms. That was wrong twice over:
the cost was understated by a factor of thirty, and 0.42 is not a value a folded AUC
can take. The measured curve replaces it.

### A short probe of a contaminated stack mostly looks clean

Shadow Replay answers *does this finding reproduce*. It cannot answer whether the stack
that produced it was clean enough for the question to mean anything. The contamination
delta does: the same Red workload, under the same concurrent Blue load, against two
deployments differing in exactly one thing — whether the parties share a model server
and a context bucket.

The clean arm is a negative control. Contamination is impossible there by construction,
so every detection it reports is a false positive.

| Session turns | Clean arm | Shared arm | Delta | Intervals |
|---|---|---|---|---|
| 1 | 0.00 [0.00, 0.11] | 0.13 [0.05, 0.30] | +0.13 | overlapping |
| 2 | 0.00 [0.00, 0.11] | 0.50 [0.33, 0.67] | +0.50 | disjoint |
| 3 | 0.00 [0.00, 0.11] | **1.00** [0.89, 1.00] | +1.00 | disjoint |
| 4 | 0.00 [0.00, 0.11] | 1.00 [0.89, 1.00] | +1.00 | disjoint |
| 6 | 0.00 [0.00, 0.11] | 1.00 [0.89, 1.00] | +1.00 | disjoint |
| 8 | 0.00 [0.00, 0.11] | 1.00 [0.89, 1.00] | +1.00 | disjoint |

*n = 30 Red sessions per cell, Wilson intervals, zero false positives in the clean arm;
`artifacts/delta.json`.*

**A one-turn probe of the contaminated stack came back clean 87% of the time. At three
turns it never did.** The window in which another tenant can overwrite the shared
context bucket opens when a session is primed and closes when that session next reads
it, so session length is the dose — and a harness that only ever takes one turn is
sampling the exact condition under which contamination is least visible.

Two honest limits. The shared-arm rate counts contamination the release scan *detected*,
and DNA sees verbatim marker propagation only, so it is a lower bound. And the clean arm
evidences the absence of *detected* contamination, which is weaker than the absence of
contamination. At one turn we report the arms as overlapping rather than claiming the
+0.13 gap: a visible difference in point estimates is not a separation.

### Shadow Replay changes the verdict

One attack, re-run in 20 freshly opened sessions, reproduced 5 times: rate 0.25, 95% CI
[0.11, 0.47] — reported as **INTERMITTENT**. A single-shot harness would have reported
the same attack as simply *true* or *false* depending on which run it happened to see.

---

## Two isolation modes, and the honest difference between them

**Process mode** (`scripts/demo.py`) runs each component as a real OS process on its own
port. A party that discovers the model's port can open a TCP connection to it, and is
stopped by the model *refusing to authenticate the caller*. The probe reports
`rejected`.

**Container mode** (`deploy/docker-compose.yml`) adds network-namespace isolation. Four
`internal: true` networks, and the gateway is the only container attached to more than
one. Remove the gateway and the graph has no edge between a party and a model. The probe
reports `no_route` — the network never carries the packet.

```
red  --[red_edge]--  gateway  --[red_model_link]--  red-model
blue --[blue_edge]--    |     --[blue_model_link]-- blue-model
```

```bash
export DOUBLEBLIND_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))")
docker compose -f deploy/docker-compose.yml up --build -d
docker compose -f deploy/docker-compose.yml run --rm red
docker compose -f deploy/docker-compose.yml run --rm blue
```

`scripts/party_shell.py` prints which outcome it saw, so the two modes are never
confused with one another in a demo.

---

## What this does not protect

Stated here, not buried. The full version with reasoning is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

- **Shared kernel.** These are containers, not VMs. A container escape defeats every
  property at once. gVisor, Kata or a microVM is the documented upgrade path.
- **The gateway is one trusted component.** It routes, redacts, logs and pads.
  Compromise it and everything falls together. It is not formally verified.
- **Microarchitectural and physical channels.** Cache, branch predictor, power, EM.
  CPU pinning raises the cost; it does not close them.
- **Resource and availability channels.** CPU and memory contention between parties is
  unmeasured.
- **Content-only detection.** DNA sees markers. Paraphrase and semantic influence carry
  none — there is a unit test asserting this blind spot so the claim cannot quietly
  drift.
- **The model is a mock.** A deterministic rule engine with one seeded stochastic
  branch, not an LLM. The channel claims are about the channel; they do not depend on
  the model being real, but nothing here is evidence about real model behaviour.
- **Checkpoints are HMAC-keyed, not signed.** Verification requires the audit key, so a
  third party cannot verify without also being able to forge. Public-key signatures are
  the upgrade.
- **Truncation of the log tail** is invisible without an externally held checkpoint.
  There is a test asserting this so it cannot regress unnoticed.

---

## Where it fails first

Ranked by likelihood, not severity.

1. **Misconfiguration re-introducing sharing.** Someone points two parties at one model
   endpoint to save memory. This is the most likely production failure — and it is the
   one DNA catches reliably. Act 3b reproduces it on demand.
2. **A leak that carries no marker.** Semantic influence rather than copied text. The
   detector stays green while the test is already contaminated.
3. **A gateway bug, not a gateway compromise.** An unpadded error path, a missed
   redaction field, a log write skipped on an exception.

---

## Layout

```
doubleblind/
  protocol.py      line-delimited JSON, HMAC auth, sequence + replay guards
  gateway.py       the mediator; every claim is enforced here
  model_server.py  mock model under test; --shared-context reproduces the leak
  party.py         Red/Blue client, and the direct-connection probe
  dna.py           canary markers, scanning, attribution
  audit.py         hash chain, keyed checkpoints, verifier
  timing.py        fixed-tick gate, distinguishing-advantage statistic
  replay.py        Shadow Replay with Wilson intervals
  delta.py         two-arm contamination experiment, clean arm as control
  proofpack.py     evidence bundle
  harness.py       brings the stack up as real processes
  api.py           HTTP API over the live engine, for the dashboard
web/
  index.html       the dashboard; no build step, no dependencies
scripts/
  demo.py            the seven-act demonstration
  measure_timing.py  the timing experiment
  measure_delta.py   the contamination experiment
  verify_log.py      independent verifier CLI
  party_shell.py     a party, from inside its container
deploy/            Dockerfile, docker-compose.yml
docs/              THREAT_MODEL.md
tests/             43 unit tests, aimed at the controls rather than the happy path
```

---

## Team

**SynapX** — Priya Jeena (systems and containers) · Manya Gupta (gateway and protocols)
· Muskan Dhami (measurement and threat model)
