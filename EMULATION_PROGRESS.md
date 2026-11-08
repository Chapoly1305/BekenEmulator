# Matter emulation checkpoint — 2026-11-08

Resume here, then read MATTER_BRINGUP.md for commands, implementation details,
and evidence boundaries. This checkpoint keeps the implementation, retained
measurements, and remaining work together for future firmware emulation.

## Working path

- Upstream baseline: e9ccbf0226d7f12b2df449a5362466deaf66d563.
- Branch: matter-commission-readout.
- Target: BK7231N application, Matter VID 0x1410 / PID 0x2351 (Quectel).
- ELF SHA256: 5118823ef2e57d35e4c3128095d9fd0a6c457824057d08b289e595513b2a5a09.
- Original retained input is outside this repository:
  /iscsi_storage/extended_storage/jchen73/MatterOverwatch-full-20261008T020300Z/MatterOverwatch/compass_evaluation/corpora/deployed_893/elfs/candidates/0c2b6e2a1500b75bdd6530df0fb5c11a79684ef3c228718c17a09d5d26dd4935_5118823ef2e57d35_elf.elf
- Fixture generation: tools/make_matter_fixture.py. The working local generated
  fixture is /tmp/mow-beken-provisioned.bin; regenerate it if absent. Its JSON
  manifest is retained as evidence/matter/test-fixture.json.
- Build: make -j4 LTO= OPT=-O1. The cstdio include repair is needed for the
  upstream ESP8266 compilation unit included in this shared build.
- Driver: tools/matter_readout.py; analysis: tools/matter_evidence.py.
- Bridge: src/matter_bridge.{h,cpp}, enabled by BEKEN_MATTER_BRIDGE_PORT.

## Host dependencies

The working patched connectedhomeip checkout is
/home/jchen73/renode-repro-26q3/matter/connectedhomeip, baseline commit
4b82451ee229cd66e54cce8b2681bad4045b8a0f plus the local Silicon Labs transport
changes. The chip-tool directory is out/renode-host-tools in that checkout.
The baseline commit alone does not reproduce those local patches.

Required host behavior: CHIP_FAKE_BLE_PORT socket transport and pairing
--pase-only support. See src/platform/Linux/ble/FakeBleTransport.{h,cpp},
examples/chip-tool/commands/pairing/PairingCommand.h, and
examples/chip-tool/commands/common/CHIPCommand.cpp there. The local build uses
chip_enable_fake_ble_transport=true and
chip_enable_fake_operational_transport=false. Enable --trace_decode 1 on
interactive start for decoded wire logging.

Tested Docker image: local/renode-host-tools:26q3,
sha256:b736f505cd044067338b806eacda7da886bbd28b25c1ae7051602def77b173b1.
This image and the patched host-tool build are external dependencies, not shipped
in this commit. The driver mounts the emulator binary and chip-tool into two
containers sharing the Docker daemon's host network. Python fixture dependencies
are pyelftools and cryptography; the driver/parser use the standard library.

## Verified results

Successful PASE and encrypted attribute reads were repeated. The wrong-PIN
control fails peer MAC verification. Runtime results:

- Basic Information ClusterRevision: 1.
- Basic Information SpecificationVersion: UNSUPPORTED_ATTRIBUTE.
- Basic Information SoftwareVersion: 2 (application version).
- PBKDFParamResponse SessionParameters.SpecificationVersion: 0x01040000.

The independent SDK TLVReader agrees with the custom evidence parser. This
chip-tool trace decoder only prints session tags 1 and 2; the actual SDK pairing
receiver also parses tag 6. Retained logs and decoded values are under
evidence/matter/{success,wrong-pin,chip-tool-decoder}/. Eight parser tests,
414 checks across seven pre-existing module suites, a 94-check backend recheck,
and a strict wrong-application-hash rejection passed. Later driver changes enable
trace output; validation.json preserves the original validated source hashes,
and checkpoint-source.json records the sources being committed.

## Scope and remaining work

This is an experimental one-executable SDK GATT bridge. Original BTP, SPAKE2+,
cryptography and Matter attribute handling execute in the application. The BLE
radio is not modeled end to end. The fixture supplies synthetic development
factory data and copies application exception vectors into the absent boot area;
application PT_LOAD bytes are unchanged. No version/revision values are injected.

Full attestation/NOC installation, Wi-Fi attachment and CASE commissioning remain
unimplemented; reports explicitly mark full_commissioning=false. Factory
attestation credentials and an operational transport are prerequisites for that
extension. No original factory or complete-flash backup is available.

For another executable, verify its full hash, chip/memory map, factory format,
BLE callback ABI, send/completion interface, free scratch RAM and stack context
before introducing another profile. Address matching alone is insufficient.
Extend profile selection and repeat positive/wrong-PIN controls before claiming
support. Boot banners, version declarations, and successful reads represent
different evidence levels.

The Nordic counterexample investigation is separate: the observed target is
nRF5340, and the initial nRF52840 Renode boot was mismatched. Only isolated Nordic
encoder execution was completed in the sibling MatterOverwatch diagnostics.
