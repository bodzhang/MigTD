// Copyright (c) 2023 - 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use anyhow::{anyhow, Error, Result};
use crypto::{hash::digest_sha384, SHA384_DIGEST_SIZE};
use igvm::IgvmFile;
use migtd::{
    config::{CONFIG_VOLUME_SIZE, MIGTD_POLICY_FFS_GUID, MIGTD_ROOT_CA_FFS_GUID},
    event_log::TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
};
use sha2::{Digest, Sha384};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
};
use td_shim_interface::td_uefi_pi::{fv, pi};
use td_shim_tools::tee_info_hash::{Manifest, TdInfoStruct};
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

const MIGTD_IMAGE_SIZE: u64 = 0x100_0000;

pub const SERVTD_TYPE_MIGTD: u16 = 0;

const SERVTD_ATTR_IGNORE_ATTRIBUTES: u64 = 0x1_0000_0000;
const SERVTD_ATTR_IGNORE_XFAM: u64 = 0x2_0000_0000;
const SERVTD_ATTR_IGNORE_MRTD: u64 = 0x4_0000_0000;
const SERVTD_ATTR_IGNORE_MRCONFIGID: u64 = 0x8_0000_0000;
const SERVTD_ATTR_IGNORE_MROWNER: u64 = 0x10_0000_0000;
const SERVTD_ATTR_IGNORE_MROWNERCONFIG: u64 = 0x20_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR0: u64 = 0x40_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR1: u64 = 0x80_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR2: u64 = 0x100_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR3: u64 = 0x200_0000_0000;

/* #[derive(Debug, Error)]
pub enum Error {
    #[error("invalid parameter area index")]
    InvalidParameterAreaIndex,
}
 */
/// Measure adding a page to TD.
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct TdxPageAdd {
    /// MEM.PAGE.ADD
    pub operation: [u8; 16],
    /// Must be aligned to a page size boundary.
    pub gpa: u64,
    /// Reserved mbz.
    pub mbz: [u8; 104],
}

const TDX_EXTEND_CHUNK_SIZE: usize = 256;

/// Measure adding a chunk of data to TD.
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct TdxMrExtend {
    /// MR.EXTEND
    pub operation: [u8; 16],
    /// Aligned to a 256B boundary.
    pub gpa: u64,
    /// Reserved mbz.
    pub mbz: [u8; 104],
    /// Data to measure.
    pub data: [u8; TDX_EXTEND_CHUNK_SIZE],
}
pub const DEFAULT_COMPATIBILITY_MASK: u32 = 0x1;
const PAGE_SIZE_4K_USIZE: usize = igvm_defs::PAGE_SIZE_4K as usize;
const SHA_384_OUTPUT_SIZE_BYTES: usize = 48;

trait IgvmFileFormat {
    fn build_mrtd_igvm(&mut self, image: &mut File, image_size: u64);
}

impl IgvmFileFormat for TdInfoStruct {
    fn build_mrtd_igvm(&mut self, image: &mut File, image_size: u64) {
        // Read the entire raw image file into memory
        image.seek(SeekFrom::Start(0)).unwrap();
        let mut file_bytes = Vec::with_capacity(image_size as usize);
        image.read_to_end(&mut file_bytes).unwrap();

        // Reuse the same vec for padding out data to 4k.
        let mut padding_vec = vec![0; PAGE_SIZE_4K_USIZE];
        let mut hasher = Sha384::new();

        // Deserialize the binary file into an IgvmFile instance
        // An in-memory IGVM file that can be used to load a guest, or serialized to the binary format
        let deserialized_binary_file = IgvmFile::new_from_binary(&file_bytes[..], None).unwrap();

        let igvm_directive_header = deserialized_binary_file.directives();

        let tdx_compatibility_mask = DEFAULT_COMPATIBILITY_MASK;
        let mut parameter_area_table = std::collections::HashMap::new();

        let mut measure_page = |gpa: u64, page_data: Option<&[u8]>| {
            // Measure the page being added.
            let page_add = TdxPageAdd {
                operation: *b"MEM.PAGE.ADD\0\0\0\0",
                gpa,
                mbz: [0; 104],
            };
            hasher.update(page_add.as_bytes());

            // Possibly measure the page contents in chunks.
            if let Some(data) = page_data {
                let data = match data.len() {
                    0 => None,
                    PAGE_SIZE_4K_USIZE => Some(data),
                    _ if data.len() < PAGE_SIZE_4K_USIZE => {
                        padding_vec.fill(0);
                        padding_vec[..data.len()].copy_from_slice(data);
                        Some(padding_vec.as_slice())
                    }
                    _ => {
                        panic!("Unexpected data size");
                    }
                };

                // Hash the contents of the 4K page, 256 bytes at a time.
                for offset in (0..igvm_defs::PAGE_SIZE_4K).step_by(TDX_EXTEND_CHUNK_SIZE) {
                    let mut mr_extend = TdxMrExtend {
                        operation: *b"MR.EXTEND\0\0\0\0\0\0\0",
                        gpa: gpa + offset,
                        mbz: [0; 104],
                        data: [0; TDX_EXTEND_CHUNK_SIZE],
                    };

                    // Copy in data for chunk if it exists.
                    if let Some(data) = data {
                        mr_extend.data.copy_from_slice(
                            &data[offset as usize..offset as usize + TDX_EXTEND_CHUNK_SIZE],
                        );
                    }
                    hasher.update(mr_extend.as_bytes());
                }
            };
        };

        // Loop over all the page data to build the digest
        for header in igvm_directive_header {
            // Skip headers that have compatibility masks that do not match TDX.
            if header
                .compatibility_mask()
                .map(|mask| mask & tdx_compatibility_mask != tdx_compatibility_mask)
                .unwrap_or(false)
            {
                continue;
            }

            match header {
                igvm::IgvmDirectiveHeader::ParameterArea {
                    number_of_bytes,
                    parameter_area_index,
                    initial_data: _,
                } => {
                    assert_eq!(
                        parameter_area_table.contains_key(&parameter_area_index),
                        false
                    );
                    assert_eq!(number_of_bytes % igvm_defs::PAGE_SIZE_4K, 0);
                    parameter_area_table.insert(parameter_area_index, number_of_bytes);
                }
                igvm::IgvmDirectiveHeader::PageData {
                    gpa,
                    compatibility_mask,
                    flags,
                    data_type: _,
                    data,
                } => {
                    assert_eq!(
                        compatibility_mask & tdx_compatibility_mask,
                        tdx_compatibility_mask
                    );

                    // Skip shared pages.
                    if flags.shared() {
                        continue;
                    }

                    // If data is unmeasured, only measure the GPA.
                    let data = if flags.unmeasured() {
                        None
                    } else {
                        Some(data.as_bytes())
                    };

                    measure_page(*gpa, data);
                }

                igvm::IgvmDirectiveHeader::ParameterInsert(param) => {
                    assert_eq!(
                        param.compatibility_mask & tdx_compatibility_mask,
                        tdx_compatibility_mask
                    );

                    let parameter_area_size = parameter_area_table
                        .get(&param.parameter_area_index)
                        .unwrap_or_else(|| panic!("Invalid parameter area index"));

                    for gpa in
                        (param.gpa..param.gpa + *parameter_area_size).step_by(PAGE_SIZE_4K_USIZE)
                    {
                        measure_page(gpa, None);
                    }
                }
                _ => {
                    // Handle all other variants by ignoring them for now
                }
            }
        }

        let hash: [u8; SHA_384_OUTPUT_SIZE_BYTES] = hasher.finalize().into();
        println!(
            "mrtd {}",
            hash.iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>()
        );
        self.mrtd.copy_from_slice(hash.as_slice());
    }
}

pub fn calculate_servtd_info_hash(
    manifest: &[u8],
    mut image: File,
    image_format: &str,
    is_ra_disabled: bool,
    servtd_attr: u64,
) -> Result<Vec<u8>, Error> {
    // Initialize the configurable fields of TD info structure.
    let manifest = serde_json::from_slice::<Manifest>(&manifest)?;
    let mut td_info = TdInfoStruct {
        attributes: manifest.attributes,
        xfam: manifest.xfam,
        mrconfig_id: manifest.mrconfigid,
        mrowner: manifest.mrowner,
        mrownerconfig: manifest.mrownerconfig,
        ..Default::default()
    };

    // Calculate the MRTD with MigTD image
    if image_format == "tdvf" {
        td_info.build_mrtd(&mut image, MIGTD_IMAGE_SIZE);
    } else if image_format == "igvm" {
        td_info.build_mrtd_igvm(&mut image, MIGTD_IMAGE_SIZE);
    } else {
        panic!("Unsupported image format: {}", image_format);
    }
    // Calculate RTMR0 and RTMR1
    td_info.build_rtmr_with_seperator(0);
    if image_format == "tdvf" {
        // Calculate RTMR2 with CFV
        let mut cfv = vec![0u8; CONFIG_VOLUME_SIZE];
        image.seek(SeekFrom::Start(0))?;
        image.read(&mut cfv)?;
        td_info
            .rtmr2
            .copy_from_slice(rtmr2(&cfv, is_ra_disabled)?.as_slice());
    }

    if (servtd_attr & SERVTD_ATTR_IGNORE_ATTRIBUTES) != 0 {
        td_info.attributes.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_XFAM) != 0 {
        td_info.xfam.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MRTD) != 0 {
        td_info.mrtd.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MRCONFIGID) != 0 {
        td_info.mrconfig_id.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MROWNER) != 0 {
        td_info.mrowner.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MROWNERCONFIG) != 0 {
        td_info.mrownerconfig.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR0) != 0 {
        td_info.rtmr0.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR1) != 0 {
        td_info.rtmr1.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR2) != 0 {
        td_info.rtmr2.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR3) != 0 {
        td_info.rtmr3.fill(0);
    }

    // Convert the TD info structure to bytes.
    let mut buffer = [0u8; size_of::<TdInfoStruct>()];
    td_info.pack(&mut buffer);

    // Calculate digest.
    digest_sha384(&buffer).map_err(|_| anyhow!("Calculate digest"))
}

fn rtmr2(cfv: &[u8], is_ra_disabled: bool) -> Result<Vec<u8>, Error> {
    let mut rtmr2 = Rtmr::new();
    if !is_ra_disabled {
        let policy = fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_POLICY_FFS_GUID)
            .ok_or(anyhow!("Unable to get policy from image"))?;
        let root_ca = fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_ROOT_CA_FFS_GUID)
            .ok_or(anyhow!("Unable to get root CA from image"))?;

        rtmr2.extend_with_raw_data(policy)?;
        rtmr2.extend_with_raw_data(root_ca)?;
    } else {
        rtmr2.extend_with_raw_data(TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT)?;
    }
    Ok(rtmr2.as_bytes().to_vec())
}

struct Rtmr {
    reg: [u8; SHA384_DIGEST_SIZE * 2],
}

impl Rtmr {
    fn new() -> Self {
        Self {
            reg: [0u8; SHA384_DIGEST_SIZE * 2],
        }
    }

    fn extend_with_raw_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let digest = calculate_digest(data)?;

        self.reg[SHA384_DIGEST_SIZE..].copy_from_slice(&digest);
        let digest = calculate_digest(&self.reg)?;
        self.reg[..SHA384_DIGEST_SIZE].copy_from_slice(&digest);

        Ok(())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.reg[..SHA384_DIGEST_SIZE]
    }
}

pub fn calculate_servtd_hash(
    servtd_info_hash: &[u8],
    servtd_type: u16,
    servtd_attr: u64,
) -> Result<Vec<u8>, Error> {
    let mut buffer = [0u8; SHA384_DIGEST_SIZE + size_of::<u16>() + size_of::<u64>()];
    let mut packed_size = 0usize;

    if servtd_info_hash.len() != SHA384_DIGEST_SIZE {
        return Err(anyhow!("servtd_info_hash length mismatch"));
    }

    buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(servtd_info_hash);
    packed_size += SHA384_DIGEST_SIZE;
    buffer[packed_size..packed_size + size_of::<u16>()].copy_from_slice(&servtd_type.to_le_bytes());
    packed_size += size_of::<u16>();
    buffer[packed_size..packed_size + size_of::<u64>()].copy_from_slice(&servtd_attr.to_le_bytes());

    digest_sha384(&buffer).map_err(|_| anyhow!("Calculate digest"))
}

fn calculate_digest(data: &[u8]) -> Result<Vec<u8>, Error> {
    let digest = digest_sha384(data).map_err(|_| anyhow!("Calculate digest"))?;
    if digest.len() != SHA384_DIGEST_SIZE {
        return Err(anyhow!("Calculate digest"));
    }

    Ok(digest)
}
