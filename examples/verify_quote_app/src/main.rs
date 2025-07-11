use az_tdx_vtpm::{hcl, imds, tdx, vtpm};
use std::ffi::c_void;
use hex;
use std::time::Duration;
use std::fs;

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

mod collateral;
use collateral::{load_collateral_if_available, set_collateral};

// Direct reproduction of the AttestLibError enum from the real attestation library
#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum AttestLibError {
    Success = 0x0000,
    Unexpected = 0x0001,
    InvalidParameter = 0x0002,
    OutOfMemory = 0x0003,
    VsockFailure = 0x0004,
    ReportFailure = 0x0005,
    ExtendFailure = 0x0006,
    NotSupported = 0x0007,
    QuoteFailure = 0x0008,
    Busy = 0x0009,
    DeviceFailure = 0x000a,
    InvalidRtmrIndex = 0x000b,
}

// Error enum matching the attestation library
#[derive(Debug)]
pub enum Error {
    InvalidRootCa,
    InitHeap,
    GetQuote,
    VerifyQuote,
    InvalidOutput,
    InvalidQuote,
    OutOfMemory,
}

// Constants matching the real attestation library
const TD_VERIFIED_REPORT_SIZE: usize = 734;

/// Constants for attestation library
pub const ATTEST_HEAP_SIZE: usize = 0x80000;

/// Intel Root CA public key (from mikbras/tdtools)
pub const INTEL_ROOT_PUB_KEY: [u8; 65] = [
    0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61,
    0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda,
    0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4,
    0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55, 0x25,
    0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4,
    0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a,
    0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55,
    0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae, 0x73,
    0x94,
];

// This is the EXACT signature of the real verify_quote_integrity function
// from src/attestation/src/binding.rs
extern "C" {
    /// Verify the integrity of MigTD's Quote and return td report of MigTD
    /// Note: all IN/OUT memory should be managed by Caller
    /// @param p_quote [in] pointer to the input buffer for td_quote
    /// @param quote_size [in] length of p_quote(in bytes), should be the real size of MigTD td quote
    /// @param root_pub_key [in] pointer to Intel Root Public Key
    /// @param root_pub_key_size [in] length of Intel Root Public Key(in bytes)
    /// @param p_tdx_report_verify [in, out] pointer to the output buffer for tdx_report
    /// @param p_tdx_report_verify_size [in, out], out_size should be = TDX_REPORT_SIZE
    ///
    /// @return Status code of the operation, one of:
    ///      - MIGTD_ATTEST_SUCCESS
    ///      - MIGTD_ATTEST_ERROR_UNEXPECTED
    fn verify_quote_integrity(
        p_quote: *const c_void,
        quote_size: u32,
        root_pub_key: *const c_void,
        root_pub_key_size: u32,
        p_tdx_report_verify: *mut c_void,
        p_tdx_report_verify_size: *mut u32,
    ) -> AttestLibError;
    // External C function for heap initialization
    fn init_heap(p_td_heap_base: *const c_void, td_heap_size: u32) -> u32;
}

/// Initialize heap for attestation library using dynamic allocation (original approach)
pub fn attest_init_heap() -> Option<usize> {
    unsafe {
        let heap_base =
            std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align(ATTEST_HEAP_SIZE, 0x1000).ok()?);

        init_heap(heap_base as *const c_void, ATTEST_HEAP_SIZE as u32);
    }

    Some(ATTEST_HEAP_SIZE)
}

/// Load quote data from file if available
pub fn load_quote_if_available() -> Option<Vec<u8>> {
    // Try to load quote from common locations
    let possible_paths = [
        "quote.bin",
        "../quote.bin", 
        "/tmp/quote.bin",
        "samples/quote.bin",
    ];
    
    for path in &possible_paths {
        if let Ok(data) = fs::read(path) {
            println!("Loaded quote from: {}", path);
            return Some(data);
        }
    }
    
    None
}
// NOTE: These functions are provided by the external C attestation library
// They should be linked via build.rs or compiler flags, not implemented in Rust

pub fn get_sample_quote() -> Vec<u8> {
    let quote = get_smart_quote_with_options(false);
    if quote.is_empty() {
        println!("⚠️ No real quote data available for sample");
    }
    quote
}

// This is the EXACT implementation of verify_quote from the real attestation library
// with the real verify_quote_integrity function call
pub fn verify_quote_real(quote: &[u8]) -> Result<Vec<u8>, Error> {
    println!("   Calling real verify_quote_integrity function...");
    
    let mut td_report_verify = vec![0u8; TD_VERIFIED_REPORT_SIZE];
    let mut report_verify_size = TD_VERIFIED_REPORT_SIZE as u32;

    // Use the Intel Root CA public key directly
    let public_key = &INTEL_ROOT_PUB_KEY;

    unsafe {
        // THIS IS THE REAL FUNCTION CALL TO verify_quote_integrity
        let result = verify_quote_integrity(
            quote.as_ptr() as *const c_void,
            quote.len() as u32,
            public_key.as_ptr() as *const c_void,
            public_key.len() as u32,
            td_report_verify.as_mut_ptr() as *mut c_void,
            &mut report_verify_size as *mut u32,
        );
        
        if result != AttestLibError::Success {
            println!("   verify_quote_integrity returned error: {:?}", result);
            return Err(Error::VerifyQuote);
        }
    }

    if report_verify_size as usize != TD_VERIFIED_REPORT_SIZE {
        println!("   Invalid output size: expected {}, got {}", TD_VERIFIED_REPORT_SIZE, report_verify_size);
        return Err(Error::InvalidOutput);
    }

    // Apply the same masking as the real implementation
    mask_verified_report_values(&mut td_report_verify[..report_verify_size as usize]);
    Ok(td_report_verify[..report_verify_size as usize].to_vec())
}

fn mask_verified_report_values(report: &mut [u8]) {
    // This is the EXACT masking logic from the real verify_quote function
    use std::ops::Range;
    
    const R_MISC_SELECT: Range<usize> = 626..630;
    const R_MISC_SELECT_MASK: Range<usize> = 630..634;
    const R_ATTRIBUTES: Range<usize> = 634..650;
    const R_ATTRIBUTES_MASK: Range<usize> = 650..666;

    if report.len() >= 666 {
        for (i, j) in R_MISC_SELECT.zip(R_MISC_SELECT_MASK) {
            report[i] &= report[j];
        }
        for (i, j) in R_ATTRIBUTES.zip(R_ATTRIBUTES_MASK) {
            report[i] &= report[j];
        }
        println!("   Applied masking to R_MISC_SELECT and R_ATTRIBUTES ranges");
    } else {
        println!("   Report too small for masking ({} bytes)", report.len());
    }
}

fn print_error(error: Error) {
    match error {
        Error::InvalidRootCa => println!("Error: Invalid Root CA"),
        Error::InitHeap => println!("Error: Init Heap"),
        Error::GetQuote => println!("Error: Get Quote"),
        Error::VerifyQuote => println!("Error: Verify Quote"),
        Error::InvalidOutput => println!("Error: Invalid Output"),
        Error::InvalidQuote => println!("Error: Invalid Quote"),
        Error::OutOfMemory => println!("Error: Out of Memory"),
    }
}

// Command line interface structure
#[derive(Parser)]
#[command(name = "verify_quote_app")]
#[command(about = "MigTD Quote Verification App - supports networking and file verification")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run in server mode (receives quotes for verification)
    Server {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,
        /// Bind address
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,
    },
    /// Run in client mode (sends quotes to server)
    Client {
        /// Server address to connect to
        #[arg(short, long, default_value = "127.0.0.1")]
        server: String,
        /// Server port to connect to
        #[arg(short, long, default_value = "8080")]
        port: u16,
        /// Send sample quote
        #[arg(long)]
        send_quote: bool,
        /// Request server's quote
        #[arg(long)]
        request_quote: bool,
    },
    /// Verify a quote from a local file
    File {
        /// Path to the quote file to verify (default: ./quote.bin)
        #[arg(short, long, default_value = "quote.bin")]
        quote_file: String,
    },
    /// Azure TDX CVM demonstration mode
    Azure,
    /// Simple IMDS test mode
    Simple,
}

// Network message protocol
#[derive(Serialize, Deserialize, Debug)]
enum NetworkMessage {
    QuoteRequest,
    QuoteResponse { 
        quote: Vec<u8> 
    },
    VerifyQuote { 
        quote: Vec<u8> 
    },
    VerificationResult { 
        success: bool, 
        verified_report: Option<Vec<u8>>,
        error: Option<String>
    },
    Ping,
    Pong,
}

// Network communication functions
async fn send_message(stream: &mut TcpStream, message: &NetworkMessage) -> Result<(), String> {
    let json = match serde_json::to_string(message) {
        Ok(json) => json,
        Err(e) => {
            println!("   ❌ JSON serialization failed: {}", e);
            return Err(format!("Serialization error: {}", e));
        }
    };
    
    let len = json.len() as u32;
    println!("   📤 Sending message: {} bytes", len);
    
    // Send length first (4 bytes)
    if let Err(e) = stream.write_all(&len.to_be_bytes()).await {
        println!("   ❌ Failed to send length: {}", e);
        return Err(format!("Failed to send length: {}", e));
    }
    
    // Send JSON message
    if let Err(e) = stream.write_all(json.as_bytes()).await {
        println!("   ❌ Failed to send message body: {}", e);
        return Err(format!("Failed to send message: {}", e));
    }
    
    if let Err(e) = stream.flush().await {
        println!("   ❌ Failed to flush stream: {}", e);
        return Err(format!("Failed to flush: {}", e));
    }
    
    println!("   ✓ Message sent successfully");
    Ok(())
}

async fn receive_message(stream: &mut TcpStream) -> Result<NetworkMessage, String> {
    println!("   📥 Waiting for message...");
    
    // Read length first (4 bytes)
    let mut len_bytes = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_bytes).await {
        println!("   ❌ Failed to read message length: {}", e);
        return Err(format!("Failed to read message length: {}", e));
    }
    
    let len = u32::from_be_bytes(len_bytes) as usize;
    println!("   📥 Expecting message of {} bytes", len);
    
    // Validate message size
    if len > 100_000_000 { // 100MB limit
        println!("   ❌ Message too large: {} bytes", len);
        return Err(format!("Message too large: {} bytes", len));
    }
    
    if len == 0 {
        println!("   ❌ Zero-length message received");
        return Err("Zero-length message".to_string());
    }
    
    // Read JSON message
    let mut buffer = vec![0u8; len];
    if let Err(e) = stream.read_exact(&mut buffer).await {
        println!("   ❌ Failed to read message body: {}", e);
        return Err(format!("Failed to read message body: {}", e));
    }
    
    let json = match String::from_utf8(buffer) {
        Ok(json) => json,
        Err(e) => {
            println!("   ❌ Invalid UTF-8 in message: {}", e);
            return Err(format!("Invalid UTF-8: {}", e));
        }
    };
    
    let message: NetworkMessage = match serde_json::from_str(&json) {
        Ok(msg) => msg,
        Err(e) => {
            println!("   ❌ JSON deserialization failed: {}", e);
            println!("   Raw JSON: {}", json);
            return Err(format!("JSON error: {}", e));
        }
    };
    
    println!("   ✓ Message received successfully");
    Ok(message)
}

// Server mode implementation
async fn run_server(bind_addr: String, port: u16) -> Result<(), String> {
    println!("=== MigTD Quote Verification Server ===");
    println!("Starting server on {}:{}", bind_addr, port);
    
    // Initialize attestation heap
    match attest_init_heap() {
        Some(heap_size) => println!("✓ Heap initialized successfully (size: {} bytes)", heap_size),
        None => {
            println!("✗ Failed to initialize attestation heap");
            return Err("Failed to initialize attestation heap".to_string());
        }
    }
    
    let listener = TcpListener::bind(format!("{}:{}", bind_addr, port)).await
        .map_err(|e| format!("Failed to bind to {}:{}: {}", bind_addr, port, e))?;
    println!("✓ Server listening on {}:{}", bind_addr, port);
    
    loop {
        let (mut stream, addr) = listener.accept().await
            .map_err(|e| format!("Failed to accept connection: {}", e))?;
        println!("\n📡 New connection from: {}", addr);
        
        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut stream).await {
                println!("❌ Error handling client {}: {}", addr, e);
            }
        });
    }
}

async fn handle_client(stream: &mut TcpStream) -> Result<(), String> {
    println!("📨 Handling new client connection");
    
    loop {
        match receive_message(stream).await {
            Ok(message) => {
                println!("📨 Received: {:?}", message);
                
                match message {
                    NetworkMessage::Ping => {
                        println!("🏓 Responding to ping");
                        if let Err(e) = send_message(stream, &NetworkMessage::Pong).await {
                            println!("❌ Failed to send pong: {}", e);
                            return Err(e);
                        }
                        println!("✓ Pong sent");
                    }
                    NetworkMessage::QuoteRequest => {
                        println!("📋 Generating quote for client");
                        let quote = get_sample_quote();
                        let response = NetworkMessage::QuoteResponse { quote };
                        if let Err(e) = send_message(stream, &response).await {
                            println!("❌ Failed to send quote: {}", e);
                            return Err(e);
                        }
                        println!("✓ Quote sent to client");
                    }
                    NetworkMessage::VerifyQuote { quote } => {
                        println!("🔍 Verifying quote from client ({} bytes)", quote.len());
                        
                        match verify_quote_real(&quote) {
                            Ok(verified_report) => {
                                println!("✅ Quote verification successful");
                                let response = NetworkMessage::VerificationResult {
                                    success: true,
                                    verified_report: Some(verified_report),
                                    error: None,
                                };
                                if let Err(e) = send_message(stream, &response).await {
                                    println!("❌ Failed to send verification result: {}", e);
                                    return Err(e);
                                }
                                println!("✓ Verification result sent");
                            }
                            Err(e) => {
                                println!("❌ Quote verification failed: {:?}", e);
                                let response = NetworkMessage::VerificationResult {
                                    success: false,
                                    verified_report: None,
                                    error: Some(format!("{:?}", e)),
                                };
                                if let Err(e) = send_message(stream, &response).await {
                                    println!("❌ Failed to send error result: {}", e);
                                    return Err(e);
                                }
                                println!("✓ Error result sent");
                            }
                        }
                    }
                    _ => {
                        println!("⚠️ Unexpected message type");
                    }
                }
            }
            Err(e) => {
                if e.contains("early eof") || e.contains("UnexpectedEof") {
                    println!("ℹ️ Client disconnected");
                    return Ok(()); // Normal disconnect
                } else {
                    println!("❌ Connection error: {}", e);
                    return Err(e);
                }
            }
        }
    }
}

// Client mode implementation
async fn run_client(server_addr: String, port: u16, send_quote: bool, request_quote: bool) -> Result<(), String> {
    println!("=== MigTD Quote Verification Client ===");
    println!("Connecting to server at {}:{}", server_addr, port);
    
    // Connect with retry logic
    let mut stream = None;
    for attempt in 1..=3 {
        println!("Connection attempt {}/3...", attempt);
        
        let connect_future = TcpStream::connect(format!("{}:{}", server_addr, port));
        match tokio::time::timeout(Duration::from_secs(5), connect_future).await {
            Ok(Ok(tcp_stream)) => {
                println!("✓ Connected successfully on attempt {}", attempt);
                stream = Some(tcp_stream);
                break;
            }
            Ok(Err(e)) => {
                println!("❌ Connection attempt {} failed: {}", attempt, e);
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            Err(_) => {
                println!("❌ Connection attempt {} timed out", attempt);
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    
    let mut stream = stream.ok_or("Failed to connect after 3 attempts")?;
    
    // Initialize heap (optional)
    match attest_init_heap() {
        Some(heap_size) => println!("✓ Client heap initialized (size: {} bytes)", heap_size),
        None => println!("⚠️ Failed to initialize attestation heap - continuing"),
    }
    
    // Test connection with ping
    println!("\n🏓 Testing connection...");
    send_message(&mut stream, &NetworkMessage::Ping).await
        .map_err(|e| format!("Failed to send ping: {}", e))?;
    
    match receive_message(&mut stream).await {
        Ok(NetworkMessage::Pong) => println!("✓ Connection test successful"),
        Ok(other) => println!("⚠️ Unexpected response to ping: {:?}", other),
        Err(e) => return Err(format!("Failed to receive pong: {}", e)),
    }
    
    // Execute requested operations
    if request_quote {
        println!("\n📞 Requesting quote from server...");
        send_message(&mut stream, &NetworkMessage::QuoteRequest).await?;
        
        match receive_message(&mut stream).await? {
            NetworkMessage::QuoteResponse { quote } => {
                println!("✅ Received quote ({} bytes)", quote.len());
                println!("   Preview: {}", hex::encode(&quote[..std::cmp::min(32, quote.len())]));
            }
            other => println!("⚠️ Unexpected response: {:?}", other),
        }
    }
    
    if send_quote {
        println!("\n📤 Sending quote for verification...");
        let quote = get_sample_quote();
        println!("   Generated local quote ({} bytes)", quote.len());
        let message = NetworkMessage::VerifyQuote { quote };
        send_message(&mut stream, &message).await?;
        
        match receive_message(&mut stream).await? {
            NetworkMessage::VerificationResult { success, verified_report, error } => {
                if success {
                    println!("✅ Server verification successful!");
                    if let Some(report) = verified_report {
                        println!("   Report size: {} bytes", report.len());
                    }
                } else {
                    println!("❌ Server verification failed");
                    if let Some(err) = error {
                        println!("   Error: {}", err);
                    }
                }
            }
            other => println!("⚠️ Unexpected response: {:?}", other),
        }
    }
    
    println!("\n✅ Client operations completed");
    Ok(())
}

fn run_file_verification(quote_file_path: String) {
    println!("=== MigTD Quote File Verification ===");
    println!("This application verifies a quote from a local file using the REAL verify_quote_integrity function");
    println!("📄 Quote file: {}", quote_file_path);
   
    // Initialize collateral for servtd_get_quote
    println!("0. Initializing collateral for servtd_get_quote...");
    if let Some(collateral_data) = load_collateral_if_available() {
        match set_collateral(collateral_data) {
            Ok(()) => println!("   ✓ Collateral data loaded successfully"),
            Err(e) => println!("   ⚠️ Failed to set collateral: {}", e),
        }
    } else {
        println!("   ⚠️ No collateral data available - servtd_get_quote may fail");
    }
    
  
    // Step 1: Initialize attestation heap
    println!("\n1. Initializing attestation heap...");
    match attest_init_heap() {
        Some(heap_size) => println!("   ✓ Heap initialized successfully (size: {} bytes)", heap_size),
        None => {
            println!("   ✗ Failed to initialize heap");
            return;
        }
    }
    
   
    // Step 2: Load quote from specified file
    println!("\n2. Loading quote from file: {}", quote_file_path);
    let quote = match std::fs::read(&quote_file_path) {
        Ok(data) => {
            println!("   ✓ Successfully loaded quote from file ({} bytes)", data.len());
            println!("   Quote preview (first 32 bytes): {}", 
                     hex::encode(&data[..std::cmp::min(32, data.len())]));
            data
        }
        Err(e) => {
            println!("   ✗ Failed to read quote file: {}", e);
            println!("   ⚠️ Falling back to smart quote generation...");
            
            let smart_quote = get_smart_quote_with_options(false);
            if smart_quote.is_empty() {
                println!("   ✗ Smart quote generation failed - no quote data available");
                return;
            }
            println!("   Generated smart quote ({} bytes)", smart_quote.len());
            smart_quote
        }
    };
    
    // Step 3: THE MAIN DEMONSTRATION - verify_quote with real verify_quote_integrity
    println!("\n3. *** CALLING REAL verify_quote_integrity FUNCTION ***");
    match verify_quote_real(&quote) {
        Ok(verified_report) => {
            println!("   ✓ Quote verification successful using REAL verify_quote_integrity!");
            println!("   Verified report size: {} bytes", verified_report.len());
            println!("   Verified report preview (first 32 bytes): {}", 
                     hex::encode(&verified_report[..std::cmp::min(32, verified_report.len())]));
            
            // Show the specific ranges that were masked
            if verified_report.len() >= 666 {
                println!("   R_MISC_SELECT (626-629): {}", 
                         hex::encode(&verified_report[626..630]));
                println!("   R_ATTRIBUTES (634-649): {}", 
                         hex::encode(&verified_report[634..650]));
            }
            
            // Save the verified report
            let output_file = format!("{}.verified", quote_file_path);
            if let Err(e) = std::fs::write(&output_file, &verified_report) {
                println!("   ⚠️ Failed to save verified report: {}", e);
            } else {
                println!("   💾 Saved verified report to: {}", output_file);
            }
        }
        Err(e) => {
            println!("   ✗ Quote verification failed");
            print_error(e);
        }
    }
    

    println!("\n=== QUOTE FILE VERIFICATION COMPLETE ===");
    println!("Verified quote from: {}", quote_file_path);
}

pub fn get_hcl_td_quote() -> Result<Vec<u8>, Error> {
    println!("   Attempting to get real Azure CVM HCL TD quote via az-tdx-vtpm...");
    
    let bytes = match vtpm::get_report() {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("   ❌ Failed to get vTPM report: {:?}", e);
            return Err(Error::GetQuote);
        }
    };
    
    let hcl_report = match hcl::HclReport::new(bytes) {
        Ok(report) => report,
        Err(e) => {
            println!("   ❌ Failed to parse HCL report: {:?}", e);
            return Err(Error::InvalidOutput);
        }
    };
    
    let var_data_hash = hcl_report.var_data_sha256();
    
    let _ak_pub = match hcl_report.ak_pub() {
        Ok(ak_pub) => ak_pub,
        Err(e) => {
            println!("   ❌ Failed to get AK public key: {:?}", e);
            return Err(Error::GetQuote);
        }
    };

    let td_report: tdx::TdReport = match hcl_report.try_into() {
        Ok(report) => report,
        Err(e) => {
            println!("   ❌ Failed to convert HCL report to TD report: {:?}", e);
            return Err(Error::InvalidOutput);
        }
    };
    
    assert!(var_data_hash == td_report.report_mac.reportdata[..32]);
    println!("   ✓ vTPM AK_pub retrieved successfully");
    println!("   ✓ Variable data hash matches TD report");
    
    let td_quote_bytes = match imds::get_td_quote(&td_report) {
        Ok(quote) => quote,
        Err(e) => {
            println!("   ❌ Failed to get TD quote from IMDS: {:?}", e);
            return Err(Error::GetQuote);
        }
    };
    
    println!("   ✓ Successfully retrieved TD quote ({} bytes)", td_quote_bytes.len());
    Ok(td_quote_bytes)
}

// Smart quote generation - use real if available, otherwise fallback to file, then mock
pub fn get_smart_quote() -> Vec<u8> {
    get_smart_quote_with_options(false)
}

/// Smart quote generation with options
pub fn get_smart_quote_with_options(force_use_file: bool) -> Vec<u8> {
    // If forced to use file, skip Azure TDX vTPM
    if force_use_file {
        if let Some(quote) = load_quote_if_available() {
            println!("   📁 Using real quote from file (forced by --use-quote-file)");
            return quote;
        } else {
            println!("   ❌ --use-quote-file specified but no quote.bin found");
            return Vec::new();
        }
    }
    
    
    // Second try: Real quote from file (from mikbras/tdtools)
    if let Some(quote) = load_quote_if_available() {
        println!("   📁 Using real quote from file (mikbras/tdtools)");
        return quote;
    }
    
    // No fallback - return empty vector
    println!("   ❌ No real quote data available (no mock fallback)");
    Vec::new()
}

// Enhanced demo that shows Azure TDX capabilities

fn run_azure_demo() {
    println!("=== Azure TDX CVM Demonstration Mode ===");
    println!("This mode demonstrates real Azure TDX CVM capabilities using az-tdx-vtpm crate");
    println!("🌟 Always uses real Azure TDX vTPM (no file fallback)\n");

    // Initialize collateral for servtd_get_quote
    println!("0. Initializing collateral for servtd_get_quote...");
    if let Some(collateral_data) = load_collateral_if_available() {
        match set_collateral(collateral_data) {
            Ok(()) => println!("   ✓ Collateral data loaded successfully"),
            Err(e) => println!("   ⚠️ Failed to set collateral: {}", e),
        }
    } else {
        println!("   ⚠️ No collateral data available - servtd_get_quote may fail");
    }
    
  
    // Step 1: Initialize attestation heap
    println!("\n1. Initializing attestation heap...");
    match attest_init_heap() {
        Some(heap_size) => println!("   ✓ Heap initialized successfully (size: {} bytes)", heap_size),
        None => {
            println!("   ✗ Failed to initialize heap");
            return;
        }
    }
      
    
    // Test 1: Try to get real HCL report
    println!("\n   1. Testing real HCL report retrieval...");
    //run_simple_inner();
    let td_quote = match get_hcl_td_quote() {
        Ok(quote) => quote,
        Err(e) => {
            println!("   ❌ Failed to get HCL td quote: {:?}", e);
            return;
        }
    };
    
    // Test 2: THE MAIN DEMONSTRATION - verify_quote with real verify_quote_integrity
    println!("\n   2. *** CALLING REAL verify_quote_integrity FUNCTION ***");
    match verify_quote_real(&td_quote) {
        Ok(verified_report) => {
            println!("   ✓ Quote verification successful using REAL verify_quote_integrity!");
            println!("   Verified report size: {} bytes", verified_report.len());
            println!("   Verified report preview (first 32 bytes): {}", 
                     hex::encode(&verified_report[..std::cmp::min(32, verified_report.len())]));
            
            // Show the specific ranges that were masked
            if verified_report.len() >= 666 {
                println!("   R_MISC_SELECT (626-629): {}", 
                         hex::encode(&verified_report[626..630]));
                println!("   R_ATTRIBUTES (634-649): {}", 
                         hex::encode(&verified_report[634..650]));
            }
            
            // Save the verified report
            let output_file = "azure_verified_report.bin";
            if let Err(e) = std::fs::write(&output_file, &verified_report) {
                println!("   ⚠️ Failed to save verified report: {}", e);
            } else {
                println!("   💾 Saved verified report to: {}", output_file);
            }
        }
        Err(e) => {
            println!("   ✗ Quote verification failed");
            print_error(e);
        }
    }
    

    println!("\n=== AZURE TDX DEMO COMPLETE ===");
}

fn run_simple() {
    println!("=== Simple IMDS Test Mode ===");
    println!("This mode runs the basic az-tdx-vtpm example\n");
    
    match run_simple_inner() {
        Ok(()) => println!("✅ Simple IMDS test completed successfully!"),
        Err(e) => println!("❌ Simple IMDS test failed: {}", e),
    }
}

fn run_simple_inner() -> Result<(), Box<dyn std::error::Error>> {
    println!("Step 1: Getting vTPM report...");
    let bytes = vtpm::get_report()?;
    println!("✓ Got vTPM report ({} bytes)", bytes.len());
    
    println!("Step 2: Creating HCL report...");
    let hcl_report = hcl::HclReport::new(bytes)?;
    let var_data_hash = hcl_report.var_data_sha256();
    let ak_pub = hcl_report.ak_pub()?;
    println!("✓ HCL report created, var_data_hash: {}", hex::encode(&var_data_hash));

    println!("Step 3: Converting to TD report...");
    let td_report: tdx::TdReport = hcl_report.try_into()?;
    assert!(var_data_hash == td_report.report_mac.reportdata[..32]);
    println!("✓ TD report conversion successful");
    println!("vTPM AK_pub: {:?}", ak_pub);
    
    println!("Step 4: Attempting to get TD quote from IMDS...");
    let td_quote_bytes = match imds::get_td_quote(&td_report) {
        Ok(quote) => {
            println!("✓ Successfully got TD quote from IMDS");
            quote
        }
        Err(e) => {
            println!("❌ IMDS call failed (expected outside Azure): {:?}", e);
            return Err(Box::new(e));
        }
    };
    
    println!("Step 5: Displaying quote information...");
    println!("TD Quote size: {} bytes", td_quote_bytes.len());
    println!("TD Quote preview (first 64 bytes): {}", 
             hex::encode(&td_quote_bytes[..std::cmp::min(64, td_quote_bytes.len())]));
    
    if td_quote_bytes.len() >= 128 {
        println!("TD Quote middle section (bytes 64-128): {}", 
                 hex::encode(&td_quote_bytes[64..std::cmp::min(128, td_quote_bytes.len())]));
    }
    
    println!("Step 6: Writing quote to file...");
    std::fs::write("td_quote.bin", &td_quote_bytes)?;
    println!("✓ TD quote saved to td_quote.bin");

    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    let result = match cli.command {
        Commands::Server { port, bind } => {
            run_server(bind, port).await
        }
        Commands::Client { server, port, send_quote, request_quote } => {
            if !send_quote && !request_quote {
                println!("⚠️ No client operations specified. Use --send-quote or --request-quote");
                println!("   Example: --send-quote --request-quote");
                return;
            }
            run_client(server, port, send_quote, request_quote).await
        }
        Commands::File { quote_file } => {
            run_file_verification(quote_file);
            return;
        }
        Commands::Azure => {
            run_azure_demo();
            return;
        }
        Commands::Simple => {
            run_simple();
            return;
        }
    };
    
    if let Err(e) = result {
        eprintln!("❌ Application error: {}", e);
        std::process::exit(1);
    }
}
