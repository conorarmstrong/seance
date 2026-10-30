// Volatility 3.2.28.2 on five Malware Analyst's Cookbook XP SP2 captures, run
// 2026-09-27 against the extracted symbol pack. Copied from its JSON output by a
// script; nothing here came from Séance. `MEM-020`, VALIDATION.md MEM-XP-3.

/// `windows.timers` on `coreflood.vmem`: `(_KTIMER address, DPC routine, period in ms)`.
pub const COREFLOOD_VOLATILITY_TIMERS: &[(u64, u64, i64)] = &[
    (0x8055a300, 0x80533bf8, 0),     // ntoskrnl ExpTimeRefreshDpcRoutine
    (0x805508d0, 0x804f3b72, 60000), // ntoskrnl IopIrpStackProfilerTimer
    (0xff128660, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x8055a400, 0x80533b58, 0),     // ntoskrnl ExpTimeZoneDpcRoutine
    (0x8055a380, 0x80533b7e, 0),     // ntoskrnl ExpCenturyDpcRoutine
    (0xff12d370, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x805530a0, 0x80509d2a, 0),     // ntoskrnl MiModifiedPageWriterTimerDispatch
    (0xff265568, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff3d8310, 0xfc1fcfdf, 0),     // NDIS -
    (0x80559160, 0x80526bac, 0),     // ntoskrnl PspJobTimeLimitsDpcRoutine
    (0xff3c9b78, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3c71a0, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3c7b40, 0xfc1fcfdf, 0),     // NDIS -
    (0xff21dd68, 0xfc7f36c4, 10000), // watchdog _imp__HalReadDmaCounter
    (0xff2a8330, 0xfc7f36c4, 10000), // watchdog _imp__HalReadDmaCounter
    (0xff157350, 0xf3b6d240, 0),     // afd -
    (0xff265620, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf3c10fa0, 0xf3c014d3, 60000), // ipsec -
    (0xf3c10b08, 0xf3c01449, 0),     // ipsec -
    (0xf3c10b70, 0xf3c01449, 0),     // ipsec -
    (0xff27bcd8, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff290b20, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf3bf1910, 0xf3ba93dd, 100),   // tcpip -
    (0xf3b1f320, 0xf3b15385, 0),     // rdbss -
    (0xf3a99260, 0xf3a91f98, 60000), // ipnat -
    (0x80ff5070, 0xf3b8148a, 0),     // netbt -
    (0x8054f288, 0x804e5aec, 0),     // ntoskrnl CcScanDpc
    (0xff1bbdf8, 0xfc7933f0, 0),     // TDI -
    (0x81027c30, 0xfc7933f0, 0),     // TDI -
    (0xff1ef230, 0xfc7933f0, 0),     // TDI -
    (0xff3d4730, 0xfc0cc4ec, 0),     // USBPORT -
    (0x80ee1730, 0xfc0cc4ec, 0),     // USBPORT -
    (0xfc2310f0, 0xfc213233, 0),     // Ntfs -
    (0xff266390, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xffafb188, 0xfc2b592e, 0),     // sr -
    (0x80558a40, 0x80523026, 1000),  // ntoskrnl PopScanIdleList
    (0xff298f20, 0xf3b8148a, 0),     // netbt -
    (0xff1d8d00, 0xf3b8148a, 0),     // netbt -
    (0xff1d8b40, 0xf3b8148a, 0),     // netbt -
    (0x80550a00, 0x804f33da, 1000),  // ntoskrnl IopTimerDispatch
    (0x8054fee0, 0x8053aad4, 0),     // ntoskrnl CmpLazyFlushDpcRoutine
    (0xff39e6b0, 0xf3b5f385, 30000), // afd -
    (0xf356c790, 0xf355d385, 0),     // srv -
    (0x80fa3688, 0xfc1fcfdf, 0),     // NDIS -
    (0xff24b580, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x80fed428, 0xfc1fcfdf, 0),     // NDIS -
    (0xff25f3e8, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff35d330, 0xfc1fd72c, 60000), // NDIS -
    (0xf32b7808, 0xf32a0202, 60000), // HTTP -
    (0xf32b7a60, 0xf32a7490, 30000), // HTTP -
    (0xf32ba040, 0xf32adae8, 0),     // HTTP -
    (0xf32ba0e0, 0xf32ab8de, 0),     // HTTP -
    (0xff3c8b40, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3ca1a0, 0xfc1fcfdf, 0),     // NDIS -
    (0xf3becbf0, 0xfc7933f0, 0),     // TDI -
    (0x80f049f8, 0xf3aa6d37, 0),     // mrxsmb -
    (0x80fc1b00, 0xf3aa6d37, 0),     // mrxsmb -
    (0xff1d8370, 0xf3b8148a, 0),     // netbt -
    (0xfc231150, 0xfc21673e, 0),     // Ntfs -
    (0x80ff0d58, 0xf3b8148a, 0),     // netbt -
    (0xff3a2828, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x80fd12b0, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
];

/// `windows.unloadedmodules` on `coreflood.vmem`, in slot order: `(name, start, end)`.
pub const COREFLOOD_VOLATILITY_UNLOADED: &[(&str, u64, u64)] = &[
    ("Sfloppy.SYS", 0xfc178000, 0xfc17b000),
    ("Cdaudio.SYS", 0xfc7b3000, 0xfc7b8000),
    ("vmdebug.sys", 0xfc66b000, 0xfc674000),
    ("splitter.sys", 0xfc9cd000, 0xfc9cf000),
    ("aec.sys", 0xf3124000, 0xf3147000),
    ("swmidi.sys", 0xf377d000, 0xf378b000),
    ("DMusic.sys", 0xf323c000, 0xf3249000),
    ("kmixer.sys", 0xf30fa000, 0xf3124000),
    ("drmkaud.sys", 0xfcab8000, 0xfcab9000),
    ("kmixer.sys", 0xf2fe0000, 0xf300a000),
    ("kmixer.sys", 0xf2ecb000, 0xf2ef5000),
];

/// `windows.timers` on `laqma.vmem`: `(_KTIMER address, DPC routine, period in ms)`.
pub const LAQMA_VOLATILITY_TIMERS: &[(u64, u64, i64)] = &[
    (0x80f30050, 0xfc0fe53c, 0),     // ks -
    (0xff265568, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff220f68, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff266390, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x8055a300, 0x80533bf8, 0),     // ntoskrnl ExpTimeRefreshDpcRoutine
    (0xfc2310f0, 0xfc213233, 0),     // Ntfs -
    (0x80558a40, 0x80523026, 1000),  // ntoskrnl PopScanIdleList
    (0xfc231150, 0xfc21673e, 0),     // Ntfs -
    (0xff1d8370, 0xf3b8148a, 0),     // netbt -
    (0xff1d8d00, 0xf3b8148a, 0),     // netbt -
    (0x80f5ce58, 0xf3b8148a, 0),     // netbt -
    (0x80550a00, 0x804f33da, 1000),  // ntoskrnl IopTimerDispatch
    (0x805508d0, 0x804f3b72, 60000), // ntoskrnl IopIrpStackProfilerTimer
    (0xff157238, 0xf3b6d240, 0),     // afd -
    (0xffafb188, 0xfc2b592e, 0),     // sr -
    (0xff39e6b0, 0xf3b5f385, 30000), // afd -
    (0x8054fee0, 0x8053aad4, 0),     // ntoskrnl CmpLazyFlushDpcRoutine
    (0xff128660, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf356c790, 0xf355d385, 0),     // srv -
    (0x80fa3688, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3d8310, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3c9b78, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3c71a0, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3c7b40, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3c8b40, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3ca1a0, 0xfc1fcfdf, 0),     // NDIS -
    (0xff27bcd8, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff265620, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf3c10fa0, 0xf3c014d3, 60000), // ipsec -
    (0xf3c10b08, 0xf3c01449, 0),     // ipsec -
    (0xf3c10b70, 0xf3c01449, 0),     // ipsec -
    (0xf3becbf0, 0xfc7933f0, 0),     // TDI -
    (0xf3a99260, 0xf3a91f98, 60000), // ipnat -
    (0x80ff0d58, 0xf3b8148a, 0),     // netbt -
    (0x80ff5070, 0xf3b8148a, 0),     // netbt -
    (0x80fc1b00, 0xf3aa6d37, 0),     // mrxsmb -
    (0xff255d88, 0xf3aa6d37, 0),     // mrxsmb -
    (0xff1d8b40, 0xf3b8148a, 0),     // netbt -
    (0x8055a400, 0x80533b58, 0),     // ntoskrnl ExpTimeZoneDpcRoutine
    (0x8055a380, 0x80533b7e, 0),     // ntoskrnl ExpCenturyDpcRoutine
    (0x80559160, 0x80526bac, 0),     // ntoskrnl PspJobTimeLimitsDpcRoutine
    (0xff24b580, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x80fed428, 0xfc1fcfdf, 0),     // NDIS -
    (0xff25f3e8, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff35d330, 0xfc1fd72c, 60000), // NDIS -
    (0xf32b7808, 0xf32a0202, 60000), // HTTP -
    (0xf32b7a60, 0xf32a7490, 30000), // HTTP -
    (0xf32ba040, 0xf32adae8, 0),     // HTTP -
    (0xf32ba0e0, 0xf32ab8de, 0),     // HTTP -
    (0xff21dd68, 0xfc7f36c4, 10000), // watchdog _imp__HalReadDmaCounter
    (0xff2a8330, 0xfc7f36c4, 10000), // watchdog _imp__HalReadDmaCounter
    (0x805530a0, 0x80509d2a, 0),     // ntoskrnl MiModifiedPageWriterTimerDispatch
    (0xff12d370, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff290b20, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf3bf1910, 0xf3ba93dd, 100),   // tcpip -
    (0xf3b1f320, 0xf3b15385, 0),     // rdbss -
    (0xff3a2828, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x8054f288, 0x804e5aec, 0),     // ntoskrnl CcScanDpc
    (0xff1bbdf8, 0xfc7933f0, 0),     // TDI -
    (0x81027c30, 0xfc7933f0, 0),     // TDI -
    (0xff1ef230, 0xfc7933f0, 0),     // TDI -
    (0xff3d4730, 0xfc0cc4ec, 0),     // USBPORT -
    (0x80ee1730, 0xfc0cc4ec, 0),     // USBPORT -
];

/// `windows.unloadedmodules` on `laqma.vmem`, in slot order: `(name, start, end)`.
pub const LAQMA_VOLATILITY_UNLOADED: &[(&str, u64, u64)] = &[
    ("Sfloppy.SYS", 0xfc178000, 0xfc17b000),
    ("Cdaudio.SYS", 0xfc7b3000, 0xfc7b8000),
    ("vmdebug.sys", 0xfc66b000, 0xfc674000),
    ("splitter.sys", 0xfc9cd000, 0xfc9cf000),
    ("aec.sys", 0xf3124000, 0xf3147000),
    ("swmidi.sys", 0xf377d000, 0xf378b000),
    ("DMusic.sys", 0xf323c000, 0xf3249000),
    ("kmixer.sys", 0xf30fa000, 0xf3124000),
    ("drmkaud.sys", 0xfcab8000, 0xfcab9000),
    ("kmixer.sys", 0xf2fe0000, 0xf300a000),
];

/// `windows.timers` on `prolaco.vmem`: `(_KTIMER address, DPC routine, period in ms)`.
pub const PROLACO_VOLATILITY_TIMERS: &[(u64, u64, i64)] = &[
    (0xffafb188, 0xfc2b592e, 0),           // sr -
    (0x80552408, 0xff12f128, -2141903832), // (no module) -
    (0x8054f288, 0x804e5aec, 0),           // ntoskrnl CcScanDpc
    (0x8055a300, 0x80533bf8, 0),           // ntoskrnl ExpTimeRefreshDpcRoutine
    (0x80fdbd88, 0xfc7f36c4, 10000),       // watchdog _imp__HalReadDmaCounter
    (0xff22c2c0, 0xfc7f36c4, 10000),       // watchdog _imp__HalReadDmaCounter
    (0xff265568, 0x80534016, 0),           // ntoskrnl ExpTimerDpcRoutine
    (0x805508d0, 0x804f3b72, 60000),       // ntoskrnl IopIrpStackProfilerTimer
    (0xf3becbf0, 0xfc7933f0, 0),           // TDI -
    (0x80ee1730, 0xfc0cc4ec, 0),           // USBPORT -
    (0xff39e6b0, 0xf3b5f385, 30000),       // afd -
    (0x80ff0d58, 0xf3b8148a, 0),           // netbt -
    (0xff128660, 0x80534016, 0),           // ntoskrnl ExpTimerDpcRoutine
    (0x80fa3688, 0xfc1fcfdf, 0),           // NDIS -
    (0xff3d8310, 0xfc1fcfdf, 0),           // NDIS -
    (0x80559160, 0x80526bac, 0),           // ntoskrnl PspJobTimeLimitsDpcRoutine
    (0xff3c9b78, 0xfc1fcfdf, 0),           // NDIS -
    (0xff3c71a0, 0xfc1fcfdf, 0),           // NDIS -
    (0xff3c7b40, 0xfc1fcfdf, 0),           // NDIS -
    (0xff265620, 0x80534016, 0),           // ntoskrnl ExpTimerDpcRoutine
    (0xf3c10fa0, 0xf3c014d3, 60000),       // ipsec -
    (0xf3c10b08, 0xf3c01449, 0),           // ipsec -
    (0xf3c10b70, 0xf3c01449, 0),           // ipsec -
    (0x80ee1730, 0xfc0cc4ec, 0),           // USBPORT -
    (0xf3a99260, 0xf3a91f98, 60000),       // ipnat -
    (0x80ff5070, 0xf3b8148a, 0),           // netbt -
    (0xff27bcd8, 0x80534016, 0),           // ntoskrnl ExpTimerDpcRoutine
    (0xff3a2828, 0x80534016, 0),           // ntoskrnl ExpTimerDpcRoutine
    (0xf356c790, 0xf355d385, 0),           // srv -
    (0xf3bf1910, 0xf3ba93dd, 100),         // tcpip -
    (0xff3d4730, 0xfc0cc4ec, 0),           // USBPORT -
    (0x80ff0d58, 0xf3b8148a, 0),           // netbt -
    (0xff24b580, 0x80534016, 0),           // ntoskrnl ExpTimerDpcRoutine
    (0x80558a40, 0x80523026, 1000),        // ntoskrnl PopScanIdleList
    (0x80fed428, 0xfc1fcfdf, 0),           // NDIS -
    (0xff25f3e8, 0x80534016, 0),           // ntoskrnl ExpTimerDpcRoutine
    (0xff35d330, 0xfc1fd72c, 60000),       // NDIS -
    (0xf32b7808, 0xf32a0202, 60000),       // HTTP -
    (0xf32b7a60, 0xf32a7490, 30000),       // HTTP -
    (0x81027c30, 0xfc7933f0, 0),           // TDI -
    (0xff1ef230, 0xfc7933f0, 0),           // TDI -
    (0xf32ba0e0, 0xf32ab8de, 0),           // HTTP -
    (0xf32ba040, 0xf32adae8, 0),           // HTTP -
    (0xff3c8b40, 0xfc1fcfdf, 0),           // NDIS -
    (0xff3ca1a0, 0xfc1fcfdf, 0),           // NDIS -
    (0x80550a00, 0x804f33da, 1000),        // ntoskrnl IopTimerDispatch
    (0x805530a0, 0x80509d2a, 0),           // ntoskrnl MiModifiedPageWriterTimerDispatch
    (0xff266390, 0x80534016, 0),           // ntoskrnl ExpTimerDpcRoutine
    (0xfc231150, 0xfc21673e, 0),           // Ntfs -
    (0x8055a400, 0x80533b58, 0),           // ntoskrnl ExpTimeZoneDpcRoutine
    (0x8055a380, 0x80533b7e, 0),           // ntoskrnl ExpCenturyDpcRoutine
    (0xff290b20, 0x80534016, 0),           // ntoskrnl ExpTimerDpcRoutine
    (0xff1bbdf8, 0xfc7933f0, 0),           // TDI -
    (0x81027c30, 0xfc7933f0, 0),           // TDI -
    (0xff1ef230, 0xfc7933f0, 0),           // TDI -
];

/// `windows.unloadedmodules` on `prolaco.vmem`, in slot order: `(name, start, end)`.
pub const PROLACO_VOLATILITY_UNLOADED: &[(&str, u64, u64)] = &[
    ("Sfloppy.SYS", 0xfc178000, 0xfc17b000),
    ("Cdaudio.SYS", 0xfc7b3000, 0xfc7b8000),
    ("vmdebug.sys", 0xfc66b000, 0xfc674000),
    ("splitter.sys", 0xfc9cd000, 0xfc9cf000),
    ("aec.sys", 0xf3124000, 0xf3147000),
    ("swmidi.sys", 0xf377d000, 0xf378b000),
    ("DMusic.sys", 0xf323c000, 0xf3249000),
    ("kmixer.sys", 0xf30fa000, 0xf3124000),
    ("drmkaud.sys", 0xfcab8000, 0xfcab9000),
    ("kmixer.sys", 0xf2fe0000, 0xf300a000),
    ("kmixer.sys", 0xf2eee000, 0xf2f18000),
    ("kmixer.sys", 0xf2d84000, 0xf2dae000),
];

/// `windows.timers` on `sality.vmem`: `(_KTIMER address, DPC routine, period in ms)`.
pub const SALITY_VOLATILITY_TIMERS: &[(u64, u64, i64)] = &[
    (0xff1d8b40, 0xf3b8148a, 0),     // netbt -
    (0xff1d8370, 0xf3b8148a, 0),     // netbt -
    (0x80f5cab8, 0xf3b8148a, 0),     // netbt -
    (0xfc2310f0, 0xfc213233, 0),     // Ntfs -
    (0x80ff0d58, 0xf3b8148a, 0),     // netbt -
    (0xff265568, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff266390, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x8054f288, 0x804e5aec, 0),     // ntoskrnl CcScanDpc
    (0x8055a300, 0x80533bf8, 0),     // ntoskrnl ExpTimeRefreshDpcRoutine
    (0x80558a40, 0x80523026, 1000),  // ntoskrnl PopScanIdleList
    (0x8054fee0, 0x8053aad4, 0),     // ntoskrnl CmpLazyFlushDpcRoutine
    (0x805508d0, 0x804f3b72, 60000), // ntoskrnl IopIrpStackProfilerTimer
    (0xff27bcd8, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff128660, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf356c790, 0xf355d385, 0),     // srv -
    (0xff290b20, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff3d8310, 0xfc1fcfdf, 0),     // NDIS -
    (0x80559160, 0x80526bac, 0),     // ntoskrnl PspJobTimeLimitsDpcRoutine
    (0x80f5ce58, 0xf3b8148a, 0),     // netbt -
    (0x80fc1b00, 0xf3aa6d37, 0),     // mrxsmb -
    (0xff3c9b78, 0xfc1fcfdf, 0),     // NDIS -
    (0xf32b7a60, 0xf32a7490, 30000), // HTTP -
    (0xf32ba040, 0xf32adae8, 0),     // HTTP -
    (0xff3c71a0, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3c7b40, 0xfc1fcfdf, 0),     // NDIS -
    (0xff265620, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf3c10fa0, 0xf3c014d3, 60000), // ipsec -
    (0xf3c10b08, 0xf3c01449, 0),     // ipsec -
    (0xf3c10b70, 0xf3c01449, 0),     // ipsec -
    (0xf3a99260, 0xf3a91f98, 60000), // ipnat -
    (0x80ff5070, 0xf3b8148a, 0),     // netbt -
    (0x8055a400, 0x80533b58, 0),     // ntoskrnl ExpTimeZoneDpcRoutine
    (0x8055a380, 0x80533b7e, 0),     // ntoskrnl ExpCenturyDpcRoutine
    (0xff12d370, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf3becbf0, 0xfc7933f0, 0),     // TDI -
    (0xff39e6b0, 0xf3b5f385, 30000), // afd -
    (0x805530a0, 0x80509d2a, 0),     // ntoskrnl MiModifiedPageWriterTimerDispatch
    (0x80f30050, 0xfc0fe53c, 0),     // ks -
    (0x80fa3688, 0xfc1fcfdf, 0),     // NDIS -
    (0xff24b580, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x80fed428, 0xfc1fcfdf, 0),     // NDIS -
    (0xff25f3e8, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff35d330, 0xfc1fd72c, 60000), // NDIS -
    (0xf3b1f320, 0xf3b15385, 0),     // rdbss -
    (0xf32ba0e0, 0xf32ab8de, 0),     // HTTP -
    (0xf32b7808, 0xf32a0202, 60000), // HTTP -
    (0xf3bf1910, 0xf3ba93dd, 100),   // tcpip -
    (0xff3c8b40, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3ca1a0, 0xfc1fcfdf, 0),     // NDIS -
    (0xff21dd68, 0xfc7f36c4, 10000), // watchdog _imp__HalReadDmaCounter
    (0xff2a8330, 0xfc7f36c4, 10000), // watchdog _imp__HalReadDmaCounter
    (0xffafb188, 0xfc2b592e, 0),     // sr -
    (0x80550a00, 0x804f33da, 1000),  // ntoskrnl IopTimerDispatch
    (0xfc231150, 0xfc21673e, 0),     // Ntfs -
    (0xff3d4730, 0xfc0cc4ec, 0),     // USBPORT -
    (0x80ee1730, 0xfc0cc4ec, 0),     // USBPORT -
    (0xff1d8d00, 0xf3b8148a, 0),     // netbt -
    (0xff3a2828, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff1bbdf8, 0xfc7933f0, 0),     // TDI -
    (0x81027c30, 0xfc7933f0, 0),     // TDI -
    (0xff1ef230, 0xfc7933f0, 0),     // TDI -
];

/// `windows.unloadedmodules` on `sality.vmem`, in slot order: `(name, start, end)`.
pub const SALITY_VOLATILITY_UNLOADED: &[(&str, u64, u64)] = &[
    ("Sfloppy.SYS", 0xfc178000, 0xfc17b000),
    ("Cdaudio.SYS", 0xfc7b3000, 0xfc7b8000),
    ("vmdebug.sys", 0xfc66b000, 0xfc674000),
    ("splitter.sys", 0xfc9cd000, 0xfc9cf000),
    ("aec.sys", 0xf3124000, 0xf3147000),
    ("swmidi.sys", 0xf377d000, 0xf378b000),
    ("DMusic.sys", 0xf323c000, 0xf3249000),
    ("kmixer.sys", 0xf30fa000, 0xf3124000),
    ("drmkaud.sys", 0xfcab8000, 0xfcab9000),
    ("kmixer.sys", 0xf2fe0000, 0xf300a000),
];

/// `windows.timers` on `silentbanker.vmem`: `(_KTIMER address, DPC routine, period in ms)`.
pub const SILENTBANKER_VOLATILITY_TIMERS: &[(u64, u64, i64)] = &[
    (0x8055a400, 0x80533b58, 0),     // ntoskrnl ExpTimeZoneDpcRoutine
    (0x8055a380, 0x80533b7e, 0),     // ntoskrnl ExpCenturyDpcRoutine
    (0xfc2310f0, 0xfc213233, 0),     // Ntfs -
    (0xff265568, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff266390, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff1d8370, 0xf3b8148a, 0),     // netbt -
    (0xff1d8d00, 0xf3b8148a, 0),     // netbt -
    (0x80f5ce58, 0xf3b8148a, 0),     // netbt -
    (0x8055a300, 0x80533bf8, 0),     // ntoskrnl ExpTimeRefreshDpcRoutine
    (0x80558a40, 0x80523026, 1000),  // ntoskrnl PopScanIdleList
    (0x805508d0, 0x804f3b72, 60000), // ntoskrnl IopIrpStackProfilerTimer
    (0x80550a00, 0x804f33da, 1000),  // ntoskrnl IopTimerDispatch
    (0x8054f288, 0x804e5aec, 0),     // ntoskrnl CcScanDpc
    (0xffafb188, 0xfc2b592e, 0),     // sr -
    (0x8054fee0, 0x8053aad4, 0),     // ntoskrnl CmpLazyFlushDpcRoutine
    (0xff128660, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf356c790, 0xf355d385, 0),     // srv -
    (0x80f16298, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x80ff0d58, 0xf3b8148a, 0),     // netbt -
    (0xff375b38, 0xf3b6d240, 0),     // afd -
    (0xff3d8310, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3c9b78, 0xfc1fcfdf, 0),     // NDIS -
    (0xf32b7a60, 0xf32a7490, 30000), // HTTP -
    (0xf32ba040, 0xf32adae8, 0),     // HTTP -
    (0xff3c71a0, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3c7b40, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3c8b40, 0xfc1fcfdf, 0),     // NDIS -
    (0xff3ca1a0, 0xfc1fcfdf, 0),     // NDIS -
    (0xff21dd68, 0xfc7f36c4, 10000), // watchdog _imp__HalReadDmaCounter
    (0xff2a8330, 0xfc7f36c4, 10000), // watchdog _imp__HalReadDmaCounter
    (0xff265620, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf3c10fa0, 0xf3c014d3, 60000), // ipsec -
    (0xf3c10b08, 0xf3c01449, 0),     // ipsec -
    (0xf3c10b70, 0xf3c01449, 0),     // ipsec -
    (0x80f049f8, 0xf3aa6d37, 0),     // mrxsmb -
    (0xff255d88, 0xf3aa6d37, 0),     // mrxsmb -
    (0xff1d8b40, 0xf3b8148a, 0),     // netbt -
    (0xf3a99260, 0xf3a91f98, 60000), // ipnat -
    (0x80ff5070, 0xf3b8148a, 0),     // netbt -
    (0x80559160, 0x80526bac, 0),     // ntoskrnl PspJobTimeLimitsDpcRoutine
    (0xff12d370, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff39e6b0, 0xf3b5f385, 30000), // afd -
    (0x80fa3688, 0xfc1fcfdf, 0),     // NDIS -
    (0x805530a0, 0x80509d2a, 0),     // ntoskrnl MiModifiedPageWriterTimerDispatch
    (0xff24b580, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x80fed428, 0xfc1fcfdf, 0),     // NDIS -
    (0xff25f3e8, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff35d330, 0xfc1fd72c, 60000), // NDIS -
    (0xf32b7808, 0xf32a0202, 60000), // HTTP -
    (0xf32ba0e0, 0xf32ab8de, 0),     // HTTP -
    (0xf3becbf0, 0xfc7933f0, 0),     // TDI -
    (0xff290b20, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf3bf1910, 0xf3ba93dd, 100),   // tcpip -
    (0xf3b1f320, 0xf3b15385, 0),     // rdbss -
    (0xff27bcd8, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff3a2828, 0x80534016, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xff1bbdf8, 0xfc7933f0, 0),     // TDI -
    (0x81027c30, 0xfc7933f0, 0),     // TDI -
    (0xff1ef230, 0xfc7933f0, 0),     // TDI -
    (0xff3d4730, 0xfc0cc4ec, 0),     // USBPORT -
    (0x80ee1730, 0xfc0cc4ec, 0),     // USBPORT -
    (0xfc231150, 0xfc21673e, 0),     // Ntfs -
];

/// `windows.unloadedmodules` on `silentbanker.vmem`, in slot order: `(name, start, end)`.
pub const SILENTBANKER_VOLATILITY_UNLOADED: &[(&str, u64, u64)] = &[
    ("Sfloppy.SYS", 0xfc178000, 0xfc17b000),
    ("Cdaudio.SYS", 0xfc7b3000, 0xfc7b8000),
    ("vmdebug.sys", 0xfc66b000, 0xfc674000),
    ("splitter.sys", 0xfc9cd000, 0xfc9cf000),
    ("aec.sys", 0xf3124000, 0xf3147000),
    ("swmidi.sys", 0xf377d000, 0xf378b000),
    ("DMusic.sys", 0xf323c000, 0xf3249000),
    ("kmixer.sys", 0xf30fa000, 0xf3124000),
    ("drmkaud.sys", 0xfcab8000, 0xfcab9000),
    ("kmixer.sys", 0xf2fe0000, 0xf300a000),
];
