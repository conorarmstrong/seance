//! Volatility 2.6.1's `timers` output for the M57 "Terry" Vista SP2 x86 non-PAE capture
//! (`terry-2009-11-16.mddramimage`), run 2026-10-22 (`sk4la/volatility`, profile `VistaSP2x86`):
//! every row as `(_KTIMER address, DPC routine, period in ms)`, module as Volatility named it.
//! Copied from the tool's text output; nothing here came from Séance. Volatility 3 cannot stack this
//! image, which is why the reference is Volatility 2 (`documentation/VALIDATION.md` `MEM-XP-5`).

pub const VISTA_VOLATILITY2_TIMERS: &[(u64, u64, u64)] = &[
    (0x81901878, 0x818419a0, 15000),  // ntoskrnl.exe
    (0x81901878, 0x818419a0, 15000),  // ntoskrnl.exe
    (0x81908bc0, 0x818ec497, 0),      // ntoskrnl.exe
    (0x81908c40, 0x818ec527, 0),      // ntoskrnl.exe
    (0x81908cc0, 0x818ec4f7, 0),      // ntoskrnl.exe
    (0x81913b80, 0x818407a0, 0),      // ntoskrnl.exe
    (0x81913f50, 0x8184603e, 250),    // ntoskrnl.exe
    (0x81914cc0, 0x8183af9b, 15000),  // ntoskrnl.exe
    (0x81914cc0, 0x8183af9b, 15000),  // ntoskrnl.exe
    (0x8193a570, 0x818330b9, 60000),  // ntoskrnl.exe
    (0x8193aea0, 0x818560a3, 0),      // ntoskrnl.exe
    (0x8193ba28, 0x818469e6, 0),      // ntoskrnl.exe
    (0x81bd4f48, 0x81bc18aa, 60000),  // hal.dll
    (0x83104508, 0x85a53c26, 10),     // tcpip.sys
    (0x83104508, 0x85a53c26, 10),     // tcpip.sys
    (0x832ee158, 0x859362f1, 0),      // ndis.sys
    (0x832ef850, 0x85efd864, 0),      // USBPORT.SYS
    (0x832f04a8, 0x859362f1, 0),      // ndis.sys
    (0x832f04a8, 0x859362f1, 0),      // ndis.sys
    (0x832fdeb0, 0x85ee6a1c, 10000),  // watchdog.sys
    (0x83371850, 0x85efd864, 0),      // USBPORT.SYS
    (0x833724a8, 0x859362f1, 0),      // ndis.sys
    (0x8337b850, 0x85efd864, 0),      // USBPORT.SYS
    (0x83385850, 0x85efd864, 0),      // USBPORT.SYS
    (0x833b0c50, 0x8a573d16, 500),    // rassstp.sys
    (0x833c3d68, 0x8a645034, 0),      // usbhub.sys
    (0x834577a0, 0x8de0972b, 0),      // spsys.sys
    (0x83467158, 0x859362f1, 0),      // ndis.sys
    (0x8346b158, 0x859362f1, 0),      // ndis.sys
    (0x8346c158, 0x859362f1, 0),      // ndis.sys
    (0x834a0920, 0x81834742, 300000), // ntoskrnl.exe
    (0x834cafd8, 0x8a645034, 0),      // usbhub.sys
    (0x834dc158, 0x859362f1, 0),      // ndis.sys
    (0x8354a020, 0x81834742, 60000),  // ntoskrnl.exe
    (0x835672a0, 0x85937c1c, 60000),  // ndis.sys
    (0x8358e5b0, 0x8a785251, 0),      // netbt.sys
    (0x8358e5b0, 0x8a785251, 0),      // netbt.sys
    (0x835a2598, 0x8593609b, 0),      // ndis.sys
    (0x8361c4c0, 0x8a785251, 0),      // netbt.sys
    (0x838c7548, 0x99a22fb4, 4000),   // usbccgp.sys
    (0x838d7340, 0x85ee6a1c, 10000),  // watchdog.sys
    (0x83a4cc68, 0x8df2e005, 0),      // srvnet.sys
    (0x83bb8958, 0x81834742, 300000), // ntoskrnl.exe
    (0x85ac09e0, 0x85a51946, 500),    // tcpip.sys
    (0x85b2c340, 0x85afa4a3, 0),      // Ntfs.sys
    (0x85b2c3a0, 0x85af7230, 0),      // Ntfs.sys
    (0x8a7c86a0, 0x8a7b7032, 0),      // afd.sys
    (0x8dc2a260, 0x8dc14005, 0),      // rdbss.sys
    (0x8dcb9200, 0x8dcb6d72, 0),      // dfsc.sys
    (0x8dda3180, 0x8dd9e1c0, 0),      // luafv.sys
    (0x8debc990, 0x8de9b907, 60000),  // HTTP.sys
    (0x8debf580, 0x8de9b82e, 60000),  // HTTP.sys
    (0x8debf680, 0x8de9b0df, 0),      // HTTP.sys
    (0x8debf960, 0x8de9b8f0, 0),      // HTTP.sys
    (0x9983e878, 0x9982f0b6, 0),      // srv.sys
    (0xa59d34a8, 0x859362f1, 0),      // ndis.sys
];
