# ADR 0001 — Detection time is an input, not an ambient read

- **Status:** Accepted
- **Date:** 2026-09-18
- **Affects:** `arpie/detection/`, `arpie/models/event.py`, `arpie/cli.py`

## Context

Three of Arpie's four detection rules are windowed: they decide by counting events
inside a time window (ARP MACs per IP in 300 s, unique ports in 10 s, packets per
second, gateway MAC changes in 600 s). Each rule read the clock itself:

```python
now = time.time()          # in every rule's inspect()
```

That couples detection to **how fast packets arrive at the engine**, which is not
a property of the network. Arpie deliberately feeds the same pipeline from two
sources — live Scapy capture and PCAP replay — and `infrastructure/capture.py`
states the intent plainly: *"this is what lets pytest run detection rules
deterministically against fixture PCAPs."*

With an ambient clock, that intent was not met. Replay consumes a capture as fast
as the disk allows, so a capture spanning 30 seconds is processed in under a
millisecond and every packet appears to have arrived at the same instant.

### Demonstration

300 ICMP packets, evenly spaced 0.1 s apart: a steady **10 packets/second**
against a 100 pps threshold. No burst exists in the data — every one-second
window holds exactly 10 packets.

| Time source | Result |
|---|---|
| Packet capture timestamp | no alert — correct |
| Wall clock (previous behaviour) | `traffic_anomaly`, **101.0 pps** reported |

A 10× overstatement, and a false positive on traffic that is an order of magnitude
below the threshold.

A second, quieter failure: `log_event` stamped the `events.ts` column with
`time.time()`, so replaying a month-old capture filed every incident under
today's date. For a tool whose deliverable is a forensic report, the incident
time was simply wrong.

### What this is not

An earlier reading of this bug claimed `sample_pcaps/demo_public_wifi.pcap`
produced a false positive at 101 pps. That was incorrect: that capture contains a
genuine 120-packet burst inside one second at offset 30 s, so its alert was a
true positive all along. The architectural defect is real, but it had to be shown
with a fixture that has a known-safe rate. Recorded here because "the demo file
false-positives" is a more alarming and less accurate claim than the truth.

## Decision

**Observation time is passed into the detection layer, never read inside it.**

1. `arpie/detection/timebase.py` defines a `Clock` port (a `typing.Protocol`),
   a `SystemClock`, a `ManualClock` for tests, and:

   ```python
   def observed_at(packet, clock=None) -> float
   ```

   which prefers the capture timestamp Scapy attaches to every packet
   (`packet.time`) and falls back to the clock only when a packet carries no
   usable timestamp.

2. Rules take the time as an argument:
   `inspect(self, packet, now: float | None = None)`.

3. `DetectionEngine.process(packet, now=None)` resolves the time **once** and
   hands the same value to all four rules, so they agree on "now" for a given
   packet, and stamps `Alert.ts` with it.

4. `log_event(..., ts=None)` persists the observation time. It still defaults to
   now for callers with no packet behind them, such as the demo seeder.

`packet.time` is the right default for both modes: under live capture it is the
sniff timestamp (≈ now), and under replay it is the original capture time.

## Consequences

**Good**

- The false positive above is gone; a genuine 1000 pps burst is still detected.
- Replay is deterministic by construction rather than by luck. Previously a
  verdict could change with machine speed or load; a test now asserts that
  stalling the feed does not change the outcome.
- Forensic reports carry the real incident time. Replaying an August capture in
  September now files events at 16:09 on 22 August, spread across the capture
  window in the order they occurred.
- Window boundaries are testable without `sleep`, via `ManualClock` and stamped
  packets.
- Rules moved closer to pure functions of `(packet, state, now)`, which is the
  direction the wider architecture is heading (see `ARCHITECTURE.md`).

**Costs**

- `inspect()` grew a parameter. Kept optional, so existing callers and tests are
  unaffected.
- `Alert.ts` no longer defaults to "when the object was constructed" in practice,
  since the engine overwrites it. Anything reading `ts` must understand it as
  observation time.
- A malformed or hostile PCAP with absurd timestamps now influences windowing.
  Acceptable: replay is an explicit, operator-initiated action on a chosen file,
  and `observed_at` rejects non-numeric and non-positive values.

**Not addressed here**

`templates/app.py` still formats the *display* time of live alerts with
`datetime.now()`, so a replayed alert shows the replay time in the UI while the
database holds the correct one. Presentation concern, folded into the
`domain/records.py` work in Phase 4 of `ARCHITECTURE.md`.

## Alternatives considered

- **Sleep during replay to reproduce original timing.** Honest but makes a 42-second
  capture take 42 seconds and a long capture unusable in tests. Rejected.
- **Inject a `Clock` into each rule and have replay drive a fake clock forward.**
  Works, but every rule then needs the clock advanced in lockstep with packets,
  which is the packet timestamp by a longer route. Rejected as indirection.
- **Scale thresholds by a replay speed factor.** Makes replay results
  incomparable with live results, defeating the point of one pipeline. Rejected.

## Verification

`tests/test_timebase.py` — 11 tests covering timestamp resolution and fallback,
the steady-rate regression, that genuine bursts still alert, independence from
feed speed, alert stamping, and that persisted events carry capture time.
