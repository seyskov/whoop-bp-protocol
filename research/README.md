# WHOOP 5 BP signal feasibility probe (private research fork)

This is a diagnostic port of the existing Dart framing/record layouts to plain
Java so a small Android APK can check a real strap without Flutter or cloud services.
The original Dart package is unchanged. The app/UI lives in the sibling
`seyskov/whoop-bp-edge` fork at `research/android-probe`.

This does not estimate blood pressure. It collects availability and integrity
counts only: CRCs, record revisions, optical rate declarations, detector-path
presence, ADC clipping and lossy R26 delta-window counts. A declared sample rate
is not a measured usable bandwidth. A morphology-pass byte is not BP validation.

Allowed commands: HELLO, GET_CLOCK, GET_DATA_RANGE, read the eight named feature
flags, one non-ACKed history preview, abort that preview, bounded revision-2 raw
start (at most 60 seconds), raw stop. Everything else is rejected structurally.
No SET_CONFIG / R22 enable, SET_CLOCK, firmware, reset, trim, or positive history ACK.
Live waveforms stay in RAM; only non-identifying availability summaries are saved.

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
