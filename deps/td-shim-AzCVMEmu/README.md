# TDX TDCALL Emulation for Azure CVM

This crate provides a drop-in replacement for the original `tdx-tdcall` crate that emulates TDX operations for MigTD development and testing in Azure TDX CVM environments.

## Architecture

The emulation library:
- **Re-exports all standard tdx-tdcall functions** unchanged for compatibility
- **Emulates MigTD-specific vmcalls** via TCP transport for inter-MigTD communication
- **Emulates GetQuote operations** using Azure IMDS (Instance Metadata Service)
- **Emulates collateral retrieval** with hardcoded DCAP collateral data
- **Maintains the exact same API** as the original tdx-tdcall
- **Uses feature flags** to enable/disable emulation

## Usage

### 1. Building with AzCVMEmu

To build MigTD with AzCVMEmu emulation for Azure TDX CVM:

```bash
# Build with AzCVMEmu feature (automatically uses correct dependencies)
cargo build --no-default-features --features AzCVMEmu

# Or use the build script
./migtdemu.sh --build
```

The `AzCVMEmu` feature automatically:
- Switches to td-shim-AzCVMEmu dependencies
- Enables TCP transport for MigTD communication
- Enables IMDS integration for attestation
- Disables real TDX hardware dependencies

### 2. Communication Architecture

**MigTD Inter-Communication (TCP):**
- Source and destination MigTD instances communicate via TCP sockets
- Used for `tdvmcall_migtd_send()` and `tdvmcall_migtd_receive()` operations
- Destination listens on configured port (default: 8001)
- Source connects to destination IP:port

**Attestation (Azure IMDS):**
- Each MigTD instance independently contacts Azure IMDS for quotes
- IMDS endpoint: `http://169.254.169.254/acc/tdquote`
- Used for `tdvmcall_get_quote()` operations
- No communication between MigTD instances for attestation

### 3. Azure IMDS Integration

The emulation uses Azure Instance Metadata Service (IMDS) for attestation:

- **GetQuote**: Extracts TDREPORT and sends to IMDS endpoint `/acc/tdquote`
- **Collateral**: Returns hardcoded DCAP collateral matching Azure TDX production environment
- **QGS Protocol**: Supports Quote Generation Service message format for backward compatibility

## Emulated Functions

### MigTD Communication (TCP-based)

- `tdvmcall_migtd_send()` - Sends data to remote MigTD via TCP
- `tdvmcall_migtd_receive()` - Receives data from remote MigTD via TCP
- `tdvmcall_migtd_waitforrequest()` - Waits for migration requests
- `tdvmcall_migtd_reportstatus()` - Reports migration status

### Attestation (IMDS-based)

- `tdvmcall_get_quote()` - Generates TD-Quote via Azure IMDS
  - **Scenario 1**: Legacy TDREPORT (1024 bytes) → Quote via IMDS
  - **Scenario 2**: QGS collateral request → Hardcoded collateral
  - **Scenario 3**: QGS quote request with TDREPORT → Quote via IMDS with QGS wrapper

### ServTD Operations

- `tdcall_servtd_rd()` - Reads emulated MSK/TDCS fields
- `tdcall_servtd_wr()` - Writes emulated MSK/TDCS fields

### System Operations

- `tdcall_sys_rd()` - Reads emulated global SYS fields
- `tdcall_sys_wr()` - Writes emulated global SYS fields

### Configuration and Firmware Volume (CFV) Emulation

The td-shim-interface provides file-based CFV emulation for policy and certificates:

- **File Reader API**: Configurable file reading interface
- **Policy Loading**: `load_policy_from_file()` - Loads migration policy from filesystem
- **Root CA Loading**: `load_root_ca_from_file()` - Loads root certificate from filesystem
- **Policy Issuer Chain**: `load_policy_issuer_chain_from_file()` - Loads policy v2 issuer chain
- **Environment Variables**: 
  - `MIGTD_POLICY_FILE` - Path to policy file
  - `MIGTD_ROOT_CA_FILE` - Path to root CA certificate
  - `MIGTD_POLICY_ISSUER_CHAIN_FILE` - Path to policy issuer chain (policy v2)

The CFV emulation replaces the firmware volume parsing in real TDX with direct file system access, allowing MigTD to load configuration from standard files instead of extracting them from the TD payload image.

### Interrupt and Hardware Emulation

The td-payload-emu provides emulation for hardware interfaces:

**Interrupt Emulation (interrupt-emu)**:
- `register()` - Register interrupt callbacks by vector
- `trigger()` - Software-triggered interrupt dispatch
- Replaces real IDT (Interrupt Descriptor Table) with callback registry

**APIC Emulation**:
- `disable()` - No-op stub for interrupt disabling
- `enable_and_hlt()` - CPU yield instead of HLT instruction
- `one_shot_tsc_deadline_mode()` - No-op timer stub
- No real APIC hardware access in emulation mode

**Memory Emulation**:
- `SharedMemory` - Heap-allocated buffers replacing shared/private memory conversion
- No real GPA (Guest Physical Address) conversion needed
- Simplifies memory management for standard runtime

**ACPI/HOB Emulation**:
- Minimal ACPI table structures (CCEL, GenericSdtHeader)
- HOB (Hand-off Block) stubs for API compatibility
- Event log emulation with file-based storage
- No firmware parsing required

All other tdx-tdcall functions pass through to the original implementation.

## Integration with MigTD

The emulation is automatically enabled when building with the `AzCVMEmu` feature:

### Build Command

```bash
# AzCVMEmu build for Azure TDX CVM
cargo build --no-default-features --features AzCVMEmu
```

### Running in Azure TDX CVM

See the main `doc/AzCVMEmu.md` for detailed instructions on:
- Setting up Azure TDX CVM environment
- Configuring network connectivity between source and destination
- Running pre-migration tests

### Testing with migtdemu.sh

Use the provided emulation test script:

```bash
# Test both source and destination MigTD
./migtdemu.sh --both

# Test source only
./migtdemu.sh --src

# Test destination only
./migtdemu.sh --dst
```

## GetQuote Protocol Support

The emulation supports three scenarios for quote generation:

### Scenario 1: Legacy TDREPORT
- Buffer contains: GHCI header (24 bytes) + TDREPORT (1024 bytes)
- Process: Extract TDREPORT → Send to IMDS `/acc/tdquote` → Return quote
- Use case: Direct quote generation without QGS protocol

### Scenario 2: QGS Collateral Request
- Buffer contains: GHCI header (24 bytes) + SERVTD_HEADER (4 bytes) + QGS message (type=2)
- Process: Return hardcoded DCAP collateral data
- Use case: Retrieve attestation collateral (certificates, CRLs, TCB info)

### Scenario 3: QGS Quote Request
- Buffer contains: GHCI header (24 bytes) + SERVTD_HEADER (4 bytes) + QGS message (type=0) + TDREPORT (1024 bytes)
- Process: Extract TDREPORT → Send to IMDS → Wrap quote in QGS response structure
- Use case: Quote generation with QGS protocol wrapper for backward compatibility

The QGS (Quote Generation Service) message format follows the standard defined in SGX DCAP qgs_msg_lib.h:
- Major version: 1
- Minor version: 1
- Message types: GET_QUOTE_REQ (0), GET_QUOTE_RESP (1), GET_COLLATERAL_REQ (2), GET_COLLATERAL_RESP (3)

## Benefits

1. **Azure TDX CVM compatibility** - Works in real Azure confidential compute environment
2. **Drop-in replacement** - Same API as original tdx-tdcall
3. **Feature-gated** - Switch between real TDX and emulated at build time
4. **IMDS integration** - Uses Azure attestation infrastructure
5. **QGS protocol support** - Backward compatible with standard quote generation service
6. **Hardcoded collateral** - Pre-configured for Azure TDX production environment

## Architecture Diagram

```
MigTD Application
       ↓
tdx-tdcall (this emulation crate)
       ↓
┌──────┴──────┐
│ Migration   │  GetQuote/Collateral
│ (TCP)       │  (Azure IMDS)
↓             ↓
Remote     Azure IMDS
MigTD      169.254.169.254
```

This design allows MigTD to run in Azure TDX CVM environment with:
- Inter-MigTD communication via TCP
- Attestation via Azure Instance Metadata Service
- No modifications to core MigTD code
