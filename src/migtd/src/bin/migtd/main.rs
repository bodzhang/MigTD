// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![no_main]

extern crate alloc;
extern "C" {
    pub fn servtd_get_quote(tdquote_req_buf: *mut core::ffi::c_void, len: u64) -> i32;
}
use core::future::poll_fn;
use core::task::Poll;

use log::info;
use migtd::event_log::TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT;
use migtd::migration::data::MigrationInformation;
use migtd::migration::session::*;
use migtd::migration::MigrationResult;
use migtd::{config, event_log, migration};
use spin::Mutex;
use sha2::{Digest, Sha384};
use tdx_tdcall::tdreport;
//use tdx_tdcall::tdreport;
use tdx_tdcall::tdx::tdvmcall_get_quote;
use td_payload::mm::shared::SharedMemory;
//use crate::attestation::binding::AttestLibError;
use core::ffi::c_void;
use alloc::vec::Vec;
use alloc::vec;

// Local trait to convert TdInfo to bytes without external dependency
trait TdInfoAsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl TdInfoAsBytes for tdreport::TdInfo {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<tdreport::TdInfo>()
            )
        }
    }
}

const MIGTD_VERSION: &str = env!("CARGO_PKG_VERSION");

// Event IDs that will be used to tag the event log
const TAGGED_EVENT_ID_POLICY: u32 = 0x1;
const TAGGED_EVENT_ID_ROOT_CA: u32 = 0x2;
const TAGGED_EVENT_ID_TEST: u32 = 0x32;


#[no_mangle]
pub extern "C" fn main() {
    #[cfg(feature = "test_stack_size")]
    {
        td_benchmark::StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, 0xd000);
    }
    runtime_main()
}

pub fn runtime_main() {
    let _ = td_logger::init();

    // Dump basic information of MigTD
    basic_info();

    // Measure the input data
    do_measurements();

    // calculate the hash of the TD info and log it
    print_td_info_hash();

    print_get_quote();
    migration::event::register_callback();

    // Query the capability of VMM
    #[cfg(not(feature = "vmcall-raw"))]
    {
        if query().is_err() {
            panic!("Migration is not supported by VMM");
        }
    }

    // Handle the migration request from VMM
    handle_pre_mig();
}

fn basic_info() {
    info!("MigTD Version - {}\n", MIGTD_VERSION);
    info!("ACC Hello World MigTD\n");
}

fn do_measurements() {
    // Get the event log recorded by firmware
    let event_log = event_log::get_event_log_mut().expect("Failed to get the event log");

    if cfg!(feature = "test_disable_ra_and_accept_all") {
        measure_test_feature(event_log);
        return;
    }

    // Get migration td policy from CFV and measure it into RMTR
    get_policy_and_measure(event_log);

    // Get root certificate from CFV and measure it into RMTR
    get_ca_and_measure(event_log);
}

fn print_td_info_hash() {
    let tdx_report: Result<tdreport::TdxReport, tdx_tdcall::TdCallError> = tdreport::tdcall_report(&[0u8; tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE]);
    //info!("tdx_report: {:?}", tdx_report);

    let td_info = tdx_report.unwrap().td_info;
    //info!("td_info: {:?}", td_info);

    let mut hasher = Sha384::new();
    hasher.update(td_info.as_bytes());

    let hash = hasher.finalize();
    info!("TD Info Hash: {:x}", hash);
}

fn print_get_quote() {
    // Example: allocate a buffer for the quote (size should be appropriate for your use case)
    let len: u64 = 16 * 4 * 1024; // 16 pages 
    let mut buf: Vec<u8> = vec![0u8; len as usize];
    //let ptr = buf.as_mut_ptr() as *mut c_void;
    let mut tdx_report = tdreport::tdcall_report(&[0u8; tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE])
        .expect("Failed to get TDX report");
    info!("Getting quote \n");
    // Copy the tdx_report data into the buffer
     /* 
    let report_ptr = &tdx_report as *const _ as *const u8;
    let report_size = core::mem::size_of_val(&tdx_report);
    if report_size > buf.len() {
        panic!("Buffer too small for tdx_report");
    }
    unsafe {
        core::ptr::copy_nonoverlapping(report_ptr.wrapping_add(24), buf.as_mut_ptr(), report_size);
    }
    let result = unsafe { servtd_get_quote(buf.as_mut_ptr() as *mut c_void, len) };
    if result == 0 {
        info!("servtd_get_quote succeeded. Quote: {:02x?}", &buf[..]);
    } else {
        info!("servtd_get_quote failed with error code: {}", result);
    }*/
    
    
    let mut shared = if let Some(shared) = SharedMemory::new(len as usize / 0x1000) {
        shared
    } else {
       panic!("Buffer too small for tdx_report");
    };
    let tdx_report_bytes: &[u8] = unsafe {
    core::slice::from_raw_parts(
        &tdx_report as *const _ as *const u8,
        core::mem::size_of_val(&tdx_report),
    )
    };
    info!("tdx_report_bytes: {:x?}", tdx_report_bytes);

    shared.as_mut_bytes()[..8].copy_from_slice(&1u64.to_le_bytes());
    shared.as_mut_bytes()[8..16].copy_from_slice(&0u64.to_le_bytes());
    shared.as_mut_bytes()[16..20].copy_from_slice(&(tdx_report_bytes.len() as u32).to_le_bytes());
    shared.as_mut_bytes()[20..24].copy_from_slice(&0u32.to_le_bytes());
    shared.as_mut_bytes()[24 .. 24+tdx_report_bytes.len()].copy_from_slice(tdx_report_bytes);

    buf.copy_from_slice(shared.as_mut_bytes());


    for (i, byte) in buf.iter().enumerate() {
        if (i > 40){
            break;
        }
        info!("{:#04x} ", byte);
    }

    let result = unsafe { servtd_get_quote(buf.as_mut_ptr() as *mut c_void, len) };
    
    if result == 0 {
    // Ensure buffer is large enough to contain the header
        if buf.len() >= 24 {
            // out_len is a little-endian u32 located at buf[20..24]
            let out_len = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
            info!("servtd_get_quote out_len (raw): {}", out_len);

            // The shared protocol uses a 4-byte internal header (SERVTD_HEADER_SIZE)
            const SERVTD_HEADER_SIZE: u32 = 4;
            if out_len >= SERVTD_HEADER_SIZE {
                let message_size = out_len - SERVTD_HEADER_SIZE;
                info!("servtd_get_quote message size (out_len - {}): {}", SERVTD_HEADER_SIZE, message_size);

                // total bytes occupied in the buffer (24 bytes header + out_len bytes of data)
                info!("total bytes used in buffer by quote header+data: {}", 24usize + out_len as usize);

                info!("servtd_get_quote succeeded. Quote response: {:02x?}", &buf[.. 24usize + out_len as usize]);
            } else {
                info!("servtd_get_quote returned small out_len: {}", out_len);
            }
        } else {
            info!("returned buffer too small to parse quote header");
        }
    } else {
        info!("servtd_get_quote failed with error code: {}", result);
    }

//for (i, byte) in shared.as_mut_bytes().iter().enumerate() {
//    info!("shared[{}] = {:#04x}", i, byte);
//}

/*let notify_registered = set_vmm_notification();

    if let Err(err) = tdvmcall_get_quote(shared.as_mut_bytes()) {
        info!("tdvmcall_get_quote failed with error: {:?}\n", err);
        info!("tdvmcall_get_quote failed with error: {}\n", err as i32);
    }
if let Err(err) = wait_for_quote_completion(notify_registered, shared.as_bytes()) {
        return err as i32;
    }    */

}


fn measure_test_feature(event_log: &mut [u8]) {
    // Measure and extend the migtd test feature to RTMR
    event_log::write_tagged_event_log(
        event_log,
        TAGGED_EVENT_ID_TEST,
        TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
    )
    .expect("Failed to log migtd test feature");
}

fn get_policy_and_measure(event_log: &mut [u8]) {
    // Read migration policy from CFV
    let policy = config::get_policy().expect("Fail to get policy from CFV\n");

    // Measure and extend the migration policy to RTMR
    event_log::write_tagged_event_log(event_log, TAGGED_EVENT_ID_POLICY, policy)
        .expect("Failed to log migration policy");
}

fn get_ca_and_measure(event_log: &mut [u8]) {
    let root_ca = config::get_root_ca().expect("Fail to get root certificate from CFV\n");

    // Measure and extend the root certificate to RTMR
    event_log::write_tagged_event_log(event_log, TAGGED_EVENT_ID_ROOT_CA, root_ca)
        .expect("Failed to log SGX root CA\n");

    attestation::root_ca::set_ca(root_ca).expect("Invalid root certificate\n");
}

fn handle_pre_mig() {
    #[cfg(any(feature = "vmcall-interrupt", feature = "vmcall-raw"))]
    const MAX_CONCURRENCY_REQUESTS: usize = 16;
    #[cfg(not(any(feature = "vmcall-interrupt", feature = "vmcall-raw")))]
    const MAX_CONCURRENCY_REQUESTS: usize = 1;

    // Set by `wait_for_request` async task when getting new request from VMM.
    static PENDING_REQUEST: Mutex<Option<MigrationInformation>> = Mutex::new(None);

    async_runtime::add_task(async move {
        loop {
            poll_fn(|_cx| {
                // Wait until both conditions are met:
                // 1. The pending request is taken by a new task
                // 2. We haven't reached the maximum concurrency limit
                if PENDING_REQUEST.lock().is_none() {
                    let current_requests = REQUESTS.lock().len();
                    if current_requests < MAX_CONCURRENCY_REQUESTS {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                } else {
                    Poll::Pending
                }
            })
            .await;

            if let Ok(request) = wait_for_request().await {
                log::info!("Setting lock for request ID: {}", request.mig_info.mig_request_id);
                *PENDING_REQUEST.lock() = Some(request);
            }
        }
    });

    loop {
        // Poll the async runtime to execute tasks
        let _ = async_runtime::poll_tasks();

        // The async task waiting for VMM response is always in the queue
        let new_request = PENDING_REQUEST.lock().take();
        log::info!("New migration request, adding task\n");
        if let Some(request) = new_request {
            log::info!("Handling migration request ID: {}\n", request.mig_info.mig_request_id);
            /*let status = exchange_msk_sync(&request)
                .map(|_| MigrationResult::Success)
                .unwrap_or_else(|e| e);
            info!("After exchange_msk_sync()\n");*/
            async_runtime::add_task(async move {
                loop{
               log::info!("Inside add task\n");
                }
                /*
                let status = exchange_msk(&request)
                    .await
                    .map(|_| MigrationResult::Success)
                    .unwrap_or_else(|e| e);

                info!("Migration request ID: {}", request.mig_info.mig_request_id);
                info!("Migration source: {}", request.mig_info.migration_source);
                info!("Target TD UUID: {:?}", request.mig_info.target_td_uuid);
                info!("Binding handle: {}", request.mig_info.binding_handle);
                info!("Migration policy ID: {}", request.mig_info.mig_policy_id);
                info!("Communication ID: {}", request.mig_info.communication_id);

                #[cfg(feature = "vmcall-raw")]
                {
                    let _ = report_status(status as u8, request.mig_info.mig_request_id).await;
                }

                #[cfg(not(feature = "vmcall-raw"))]
                {
                    let _ = report_status(status as u8, request.mig_info.mig_request_id);
                }
                
                REQUESTS.lock().remove(&request.mig_info.mig_request_id);*/
            });
        }
        log::info!("Polling tasks()\n");
        let _ = async_runtime::poll_tasks();
        sleep();
    }
}

fn sleep() {
    use td_payload::arch::apic::{disable, enable_and_hlt};
    info!("Inside sleep\n");
    enable_and_hlt();
    info!("After enable_and_hlt()\n");
    disable();
    info!("After disable()\n");
}

#[cfg(test)]
fn main() {}
// FIXME: remove when https://github.com/Amanieu/minicov/issues/12 is fixed.
#[cfg(all(feature = "coverage", target_os = "none"))]
#[no_mangle]
static __llvm_profile_runtime: u32 = 0;

#[cfg(any(feature = "test_stack_size", feature = "test_heap_size"))]
fn test_memory() {
    #[cfg(feature = "test_stack_size")]
    {
        let value = td_benchmark::StackProfiling::stack_usage().unwrap();
        td_payload::println!("max stack usage: {}", value);
    }
    #[cfg(feature = "test_heap_size")]
    {
        let value = td_benchmark::HeapProfiling::heap_usage().unwrap();
        td_payload::println!("max heap usage: {}", value);
    }
}
