# WHOOP 5 BP signal feasibility probe (private research fork)

This is a diagnostic port of the existing Dart framing/record layouts to plain
Java so a small Android APK can check a real strap without Flutter or cloud services.
The original Dart package is unchanged. The app/UI lives in the sibling
`seyskov/whoop-bp-edge` fork at `research/android-probe`.

This does not estimate blood pressure. It collects availability and integrity
counts only: CRCs, record revisions, optical rate declarations, detector-path
presence, ADC clipping and lossy R26 delta-window counts. It also supports
bounded local historical R26 capture and **RAM-only live type-20** inspection.
A declared sample rate
is not a measured usable bandwidth. A morphology-pass byte is not BP validation.

Allowed commands: HELLO, GET_CLOCK, GET_DATA_RANGE, read the eight named feature
flags, one non-ACKed history preview, abort that preview, bounded revision-2 raw
start (at most 60 seconds), raw stop, temporary optical-live and realtime-HR
ON/OFF. The application pairs both toggles with OFF at the end of a bounded
session. Everything else is rejected structurally.
No SET_CONFIG / R22 enable, SET_CLOCK, firmware, reset, trim, or positive history ACK.
Live waveforms stay in RAM; only aggregate live statistics are saved. Requested
historical R26 windows may be stored locally by the app. No raw capture is committed.

`LiveOpticalAudit` recognizes only 0x2B/20 inners with the existing 2128-byte
v20 geometry and records explicit rate/flag disagreement rather than hiding it.
It tracks detector paths separately, splits discontinuous/changing-config
segments, and performs descriptive DFT checks on a worker. No BP, notch,
vascular-age or clinically validated quality classification is returned.
The strongest frequency in 0.5–4Hz is not guaranteed to be the pulse: slow
drift/motion can dominate. Agreement with device HR is corroboration, not an
independent ECG validation, and autocorrelation can be high on slow drift.

The history preview observes only the first available burst and never advances
the trim cursor. Not seeing R20/R26 there proves neither their absence on the
strap nor a hardware limitation. The persistent R22 enable path is a separate,
partly irreversible experiment and is intentionally unavailable in this probe.

Run the JVM tests (JDK 17):

```sh
mkdir -p /tmp/whoop-probe-test
javac -d /tmp/whoop-probe-test research/java/org/whoopbp/probe/*.java
java -cp /tmp/whoop-probe-test org.whoopbp.probe.Gen5ProbeTest
```

Source layout reference: upstream protocol commit
`b4fde6ab5589e53154b808f8b2bbb4d01d9c15b5`.
AGPL-3.0, like the parent repository. No claim of association with WHOOP or OpenStrap.
