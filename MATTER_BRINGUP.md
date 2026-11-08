# BK7231N Matter PASE and attribute readout

The retained BK7231N application now completes a real chip-tool PASE handshake
and answers encrypted Interaction Model reads. This implements the PASE-only
measurement flow used by MatterOverwatch's Silicon Labs harness. **Full fabric
commissioning (attestation, NOC installation, network attachment, and CASE) is
not implemented or claimed.**

Observed on executable SHA256
`5118823ef2e57d35e4c3128095d9fd0a6c457824057d08b289e595513b2a5a09`:

| Observation | Runtime result |
| --- | --- |
| PASE with matching test PIN | Successful |
| Basic Information ClusterRevision, endpoint 0 / 0x28 / 0xFFFD | 1 |
| Basic Information SpecificationVersion, endpoint 0 / 0x28 / 0x0015 | UNSUPPORTED_ATTRIBUTE |
| Basic Information SoftwareVersion, endpoint 0 / 0x28 / 0x0009 | 2 (vendor application version) |
| PBKDFParamResponse SessionParameters tag 6 | 0x01040000 (1.4.0) |
| PASE with incorrect PIN | Peer MAC verification fails; no successful attribute reads |

This is a dynamic counterexample to using low Basic Information ClusterRevision
as proof that a newer SpecificationVersion cannot be recovered. It does not
identify a unique SDK commit or establish physical-device conformance.

## Reproduce

Build on Linux:

```sh
make -j4 LTO= OPT=-O1
python3 -m venv .venv
.venv/bin/pip install pyelftools cryptography
.venv/bin/python tools/make_matter_fixture.py /path/to/retained.elf /tmp/beken-test.bin
python3 tools/matter_readout.py /tmp/beken-test.bin \
  --output runs/my-readout \
  --chip-dir /path/to/connectedhomeip/out/renode-host-tools
```

The host tools must include the existing Silicon Labs patches for
`CHIP_FAKE_BLE_PORT` and `--pase-only`. The tested image is
`local/renode-host-tools:26q3`; select another compatible image with
`--host-image`. Both emulator and chip-tool run on the Docker daemon's host
network and communicate only via a loopback socket. The launcher removes its
own uniquely named containers on completion. Use a different `--port` for
independent runs. Raw emulator and chip-tool logs, result.json, evidence.json,
and executable/flash digests are retained in the output directory.

Negative control (expected nonzero exit, PASE false):

```sh
python3 tools/matter_readout.py /tmp/beken-test.bin \
  --output runs/wrong-pin --port 3514 --passcode 20202022 \
  --chip-dir /path/to/connectedhomeip/out/renode-host-tools
```

## Emulation boundary

`BEKEN_MATTER_BRIDGE_PORT` explicitly enables the experimental profile. Without
it the existing emulator behavior is unchanged. The bridge checks the complete
loaded application's SHA256 before enabling any address-specific behavior and
rejects every other executable. This is currently a one-executable profile,
not general support for all Beken Matter firmware.

Unlike Silicon Labs' Renode BleCentralBridge, this bridge operates at the Beken
SDK GATT callback boundary; the current Beken BLE core has no radio connection
model. It forwards C1 writes and C2 subscriptions to the firmware's registered
BLE callback at 0x36a18, captures its SDK send call at 0xb37bc, and supplies
send-completion callbacks only after socket transmission. The host framing is
the same one-byte type / uint16 little-endian length protocol used by Silicon
Labs. BTP negotiation, SPAKE2+, session cryptography, Matter message handling,
and attribute reads all execute the original firmware code. The bridge contains
no returned version/revision values and does not fabricate successful PASE or
attribute responses.

Callbacks run in a saved idle-task context with a separate scratch stack. The
firmware's RTOS can preempt them to process CHIP events; the original context is
restored when the callback returns. Scratch RAM is outside this application's
observed heap. The profile invokes the existing `matter_show` command and the
application's existing open-commissioning-window wrapper, including its CHIP
stack lock. Firmware SHA256, addresses, and ABI must be reverified before adding
another profile.

## Synthetic provisioning

The retained ELF lacks bootloader, factory data, and calibration partitions.
The fixture generator copies its 64-byte application vector block to address
zero to supply absent exception routing. The PT_LOAD application bytes remain
identical. No instruction pattern in this application matches the emulator's
upstream automatic LDM-stub patch.

The generator creates development commissioning credentials (PIN 20202021,
discriminator 3840, 1000 iterations, explicit deterministic test salt). SPAKE2+
derivation follows connectedhomeip's `scripts/tools/spake2p/spake2p.py`, using
Python cryptography for the same P-256 operation. The original firmware's factory
reader determines the container layout: partition 0xA at 0x1FD000 plus 0x1000,
0x90-byte offset/length header. The firmware reads these bytes through its own
flash driver and prints a valid setup QR code. No example application replaces
the original application; compiling a different firmware was unnecessary for
this measurement. The fixture has no attestation credentials and is not a
recovered device flash image. It supplies no Matter version or ClusterRevision
fields.

The flash generator's sidecar JSON records credentials, layout, and hashes.
The same immutable application with different host PINs passes/fails PASE as
expected. These test credentials are public and unsuitable for real devices.

## Evidence and validation

See `evidence/matter/` for retained successful/incorrect-PIN runs and the strict
hash rejection. The report parser reconstructs BTP messages and parses the
actual unsecured PBKDFParamResponse TLV; it does not search for a version byte
substring. Attribute results require a received ReportData message with the
matching endpoint/cluster/attribute path. Missing responses remain UNRESOLVED.

```sh
python3 -m unittest discover -s tests/matter -v
make -j4 unittests LTO= OPT=-O1
./unittests chips timers gpio_button gpio_emulator image_loader watchdog backends
```

The initial checks passed eight evidence-parser tests and 414 checks across the
seven existing module suites. The PIN negative control rejects the wrong peer
MAC. Full commissioning remains separate work requiring attestation data and an
operational transport; `full_commissioning` is explicitly false in every report.

## Independent SDK decoder cross-check

A follow-up run enabled chip-tool tracing on `interactive start --trace_decode 1`.
Its received PBKDFParamResponse payload is retained in
`evidence/matter/chip-tool-decoder/chip-tool.log`. This chip-tool revision's
`examples/common/tracing/decoder/secure_channel/Decoder.cpp::DecodeSEDParams`
prints only session tags 1 and 2, then exits the container, skipping tags 3–7.
Thus its human-readable trace does not print SpecificationVersion.

The received payload was independently decoded using the SDK's own Python
`src/controller/python/matter/tlv/TLVReader`, without the custom evidence parser.
It returns root[5][6] = 17039360 (0x01040000). The official schema
`src/lib/format/protocol_messages.matter::SessionParameterStruct` and actual
C++ receiver `PairingSession::DecodeSessionParametersIfPresent` both identify
context tag 6 as a uint32 SpecificationVersion. The SDK decoder output is retained
as `evidence/matter/chip-tool-decoder/official-tlv-decoder.json`.
