//! SMBIOS measurement for RTMR0 event #14 (`EV_EFI_HANDOFF_TABLES`).
//!
//! OVMF/TDVF logs a 32-byte handoff-pointer as the event data but records a
//! **precomputed** digest = SHA-384 of a *filtered* copy of the SMBIOS structure
//! table. The filter is EDK2's `MdeModulePkg/Universal/SmbiosMeasurementDxe`:
//! per structure type it blanks volatile/host-varying fields — string fields to
//! spaces (0x20) with their reference byte zeroed, numeric fields zeroed — and
//! zeroes all-but-4-byte-header for OEM types (>= 128) and a set of NULL-filter
//! types. The measured buffer is the full structure table through type 127.
//!
//! Note: the measured table carries the Type-4 Processor ID (CPUID leaf-1), which
//! is NOT filtered — so #14 depends on the guest CPU. See the CPU-reconstruction
//! path for how measurement generation pins that deterministically.

use crate::util::measure_sha384;

struct Field {
    off: usize,
    size: usize,
    is_string: bool,
}

// Per-type blacklists mirroring mSmbiosFilter*BlackList in edk2 (stable202605).
// Only the types QEMU emits for our machines carry a filter here (1/2/3/4/17);
// the NULL-filter set and OEM range are handled generically below. Types
// 22/23/27/39 exist in EDK2's table but never appear in our SMBIOS, so omitting
// them yields the identical measured digest (validated in tests).
fn filter_for(t: u8) -> Option<&'static [Field]> {
    const T1: &[Field] = &[
        Field { off: 0x07, size: 1, is_string: true },  // SerialNumber
        Field { off: 0x08, size: 16, is_string: false }, // Uuid
        Field { off: 0x18, size: 1, is_string: false }, // WakeUpType
    ];
    const T2: &[Field] = &[
        Field { off: 0x07, size: 1, is_string: true }, // SerialNumber
        Field { off: 0x0a, size: 1, is_string: true }, // LocationInChassis
    ];
    const T3: &[Field] = &[
        Field { off: 0x07, size: 1, is_string: true }, // SerialNumber
        Field { off: 0x08, size: 1, is_string: true }, // AssetTag
    ];
    const T4: &[Field] = &[
        Field { off: 0x20, size: 1, is_string: true },  // SerialNumber
        Field { off: 0x21, size: 1, is_string: true },  // AssetTag
        Field { off: 0x22, size: 1, is_string: true },  // PartNumber
        Field { off: 0x23, size: 1, is_string: false }, // CoreCount
        Field { off: 0x24, size: 1, is_string: false }, // EnabledCoreCount
        Field { off: 0x25, size: 1, is_string: false }, // ThreadCount
        Field { off: 0x2a, size: 2, is_string: false }, // CoreCount2
        Field { off: 0x2c, size: 2, is_string: false }, // EnabledCoreCount2
        Field { off: 0x2e, size: 2, is_string: false }, // ThreadCount2
        Field { off: 0x11, size: 1, is_string: false }, // Voltage
        Field { off: 0x16, size: 2, is_string: false }, // CurrentSpeed
    ];
    const T17: &[Field] = &[
        Field { off: 0x18, size: 1, is_string: true }, // SerialNumber
        Field { off: 0x19, size: 1, is_string: true }, // AssetTag
        Field { off: 0x1a, size: 1, is_string: true }, // PartNumber
    ];
    match t {
        0x01 => Some(T1),
        0x02 => Some(T2),
        0x03 => Some(T3),
        0x04 => Some(T4),
        0x11 => Some(T17),
        _ => None,
    }
}

// Types whose EDK2 filter entry is NULL == zero every field except the 4-byte header.
const NULL_FILTER: &[u8] = &[0x0b, 0x0f, 0x12, 0x1f, 0x21];
const SMBIOS_OEM_BEGIN: u8 = 128;

/// Apply the EDK2 SmbiosMeasurementDxe filter to a full SMBIOS structure table.
fn filter_smbios(buf: &[u8]) -> Vec<u8> {
    let mut b = buf.to_vec();
    let mut i = 0usize;
    while i + 4 <= b.len() {
        let t = b[i];
        let ln = b[i + 1] as usize;
        if ln < 4 {
            break;
        }
        // Find the terminating double-NUL that ends this structure's string set
        // (a structure with no strings has it immediately after the formatted area).
        let mut e = i + ln;
        while e + 1 < b.len() && !(b[e] == 0 && b[e + 1] == 0) {
            e += 1;
        }
        // Locate the structure's strings (start, len), 1-indexed by SMBIOS string id,
        // strictly within [i+ln, e) so we never spill into the next structure.
        let mut strs: Vec<(usize, usize)> = Vec::new();
        let mut k = i + ln;
        while k < e {
            let st = k;
            while k < e && b[k] != 0 {
                k += 1;
            }
            strs.push((st, k - st));
            k += 1; // skip the string's NUL terminator
        }
        let next = e + 2;

        if t >= SMBIOS_OEM_BEGIN || NULL_FILTER.contains(&t) {
            for x in (i + 4)..(i + ln) {
                b[x] = 0;
            }
        } else if let Some(fields) = filter_for(t) {
            for f in fields {
                // EDK2 skips fields not present in this structure's formatted area.
                if ln >= f.off + f.size {
                    if f.is_string {
                        let sid = b[i + f.off] as usize;
                        if sid != 0 && sid <= strs.len() {
                            let (st, sl) = strs[sid - 1];
                            for x in st..(st + sl) {
                                b[x] = 0x20; // SetMem(String, StringLen, ' ')
                            }
                        }
                    }
                    for x in (i + f.off)..(i + f.off + f.size) {
                        b[x] = 0; // ZeroMem(field)
                    }
                }
            }
        }
        i = next;
        if t == 127 {
            break;
        }
    }
    b
}

// OVMF (edk2-stable202605, OVMF.inteltdx.fd) publishes QEMU's SMBIOS structures plus
// its own Type-0 (BIOS Information: vendor "EDK II", the pinned build's version/date)
// and re-emits the end-of-table (Type-127, handle 0xfeff). QEMU's dumped smbios_tables
// carries neither, so the *measured* table = QEMU structures (minus QEMU's own Type-127)
// followed by this OVMF tail. Tied to the pinned firmware — re-extract from a real boot's
// /sys/firmware/dmi if OVMF.inteltdx.fd changes.
const OVMF_SMBIOS_TAIL_HEX: &str = "001a0000010200e803000800000000000000001c0000ffff000045444b20494900756e6b6e6f776e0030322f30322f3230323200007f04fffe0000";

fn reconstruct_ovmf_smbios(qemu: &[u8]) -> Vec<u8> {
    let tail = hex::decode(OVMF_SMBIOS_TAIL_HEX).expect("valid OVMF smbios tail hex");
    let mut i = 0usize;
    while i + 4 <= qemu.len() {
        let ln = qemu[i + 1] as usize;
        if ln < 4 {
            break;
        }
        if qemu[i] == 127 {
            // Replace QEMU's end-of-table with the OVMF tail (Type-0 + Type-127).
            let mut out = qemu[..i].to_vec();
            out.extend_from_slice(&tail);
            return out;
        }
        let mut e = i + ln;
        while e + 1 < qemu.len() && !(qemu[e] == 0 && qemu[e + 1] == 0) {
            e += 1;
        }
        i = e + 2;
    }
    let mut out = qemu.to_vec();
    out.extend_from_slice(&tail);
    out
}

/// SHA-384 of an already-published SMBIOS table, EDK2-filtered.
fn measure_filtered(full_table: &[u8]) -> Vec<u8> {
    measure_sha384(&filter_smbios(full_table))
}

/// RTMR0 event #14 digest from QEMU's dumped `smbios_tables`: reconstruct the
/// OVMF-published table (add the OVMF tail), then SHA-384 the EDK2-filtered form.
pub fn measure_smbios(qemu_smbios: &[u8]) -> Vec<u8> {
    measure_filtered(&reconstruct_ovmf_smbios(qemu_smbios))
}

/// Overwrite every SMBIOS Type-4 "Processor ID" (8 bytes at structure offset 8) with
/// `processor_id`. Used to pin RTMR0 #14 to the production CPU's CPUID leaf-1 when the
/// dump runs under a KVM host whose guest CPUID can't be overridden (`ds`/`ss` gating).
pub fn patch_type4_processor_id(smbios: &mut [u8], processor_id: &[u8; 8]) {
    let mut i = 0usize;
    while i + 4 <= smbios.len() {
        let t = smbios[i];
        let ln = smbios[i + 1] as usize;
        if ln < 4 {
            break;
        }
        if t == 4 && ln >= 16 {
            smbios[i + 8..i + 16].copy_from_slice(processor_id);
        }
        let mut e = i + ln;
        while e + 1 < smbios.len() && !(smbios[e] == 0 && smbios[e + 1] == 0) {
            e += 1;
        }
        i = e + 2;
        if t == 127 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // node1, real Intel Emerald boot. DMI = the OVMF-published table (from
    // /sys/firmware/dmi/tables/DMI, includes OVMF's Type-0); QEMU = the raw
    // etc/smbios/smbios-tables the fork dumps (no Type-0, QEMU's own Type-127).
    // The measured #14 in the CCEL is 6801eb1d…
    const DMI_HEX: &str = "011b00010102030400000000000000000000000000000000060000436875746573005444582d564d00312e3000300000020f00020102030400010000030a00436875746573005444582d564d00312e30003000000316000301010203000303030200000000000000000043687574657300312e3000300000042a00040103fe02f2060c00fffba91f03000000d007d0074101ffffffffffff0000003e3e3e0200010043505520300051454d550070632d7133352d31302e320000042a01040103fe02f2060c00fffba91f03000000d007d0074101ffffffffffff0000003e3e3e0200010043505520310051454d550070632d7133352d31302e3200001017001001030600008046feff010000000000000000000000112800110010feffffffffffff7f090001000702000000020000000000a01100000000000000000044494d4d20300051454d550000131f001300000000ffff1f00001001000000000000000000000000000000000000131f011300004000ffff9f46001001000000000000000000000000000000000000200b0020000000000000000000001a0000010200e803000800000000000000001c0000ffff000045444b20494900756e6b6e6f776e0030322f30322f3230323200007f04fffe0000";
    const QEMU_HEX: &str = "011b00010102030400000000000000000000000000000000060000436875746573005444582d564d00312e3000300000020f00020102030400010000030a00436875746573005444582d564d00312e30003000000316000301010203000303030200000000000000000043687574657300312e3000300000042a00040103fe02f2060c00fffba91f03000000d007d0074101ffffffffffff0000003e3e3e0200010043505520300051454d550070632d7133352d31302e320000042a01040103fe02f2060c00fffba91f03000000d007d0074101ffffffffffff0000003e3e3e0200010043505520310051454d550070632d7133352d31302e3200001017001001030600008046feff010000000000000000000000112800110010feffffffffffff7f090001000702000000020000000000a01100000000000000000044494d4d20300051454d550000131f001300000000ffff1f00001001000000000000000000000000000000000000131f011300004000ffff9f46001001000000000000000000000000000000000000200b00200000000000000000007f04007f0000";
    const CCEL_14: &str = "6801eb1ddd477a6a52232e291d4287b0e8f047d8f289546a0621cede30a9913d52c5eff1d8e299b064a9162fbe2f6f76";

    #[test]
    fn filter_of_published_dmi_matches_ccel() {
        // The EDK2 filter alone, on the final published table.
        let dmi = hex::decode(DMI_HEX).unwrap();
        assert_eq!(hex::encode(measure_filtered(&dmi)), CCEL_14);
    }

    #[test]
    fn measure_from_qemu_dump_matches_ccel() {
        // The real code path: QEMU's dumped table → OVMF reconstruction → filter.
        let qemu = hex::decode(QEMU_HEX).unwrap();
        assert_eq!(hex::encode(measure_smbios(&qemu)), CCEL_14);
    }
}
