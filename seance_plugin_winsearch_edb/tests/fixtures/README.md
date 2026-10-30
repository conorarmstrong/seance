# Windows Search encoded-value fixtures

Each file is the raw `System_Search_AutoSummary` value libesedb 0.2.7 returns
for one row of `SystemIndex_0A` in the NIST CFReDS Data Leakage PC's
`Windows.edb` (MFT entry 490, Windows 7, SHA-256
`f29fa5c3d6a7bf5c851286abee5d7742ce02c55d84b1020badb67b2ac8080ca1`). "Row" is
the walk index (`DocID` is row + 1). Unedited.

| File | Bytes | Form after de-obfuscation | SHA-256 |
|---|---|---|---|
| `data_leakage_autosummary_row2.bin` | 131 | type 1, 8-bit text ("Choose which programs…") | `d6593bc942f98b22158166c595c35ff1abedc4471869b710677a4d70d32753d4` |
| `data_leakage_autosummary_row24.bin` | 160 | type 0, runs (Chess description, one U+2019) | `82e291267b1de533823b4bf8bbbebfd886bdb098722f710095802ae58faa1a46` |
| `data_leakage_autosummary_row388.bin` | 458 | type 3, not decoded | `09734e34b56a078b299f8c0c08f53aa3d9db68ed6d4951d66750a97a1483515e` |
| `data_leakage_autosummary_row391.bin` | 293 | type 0, runs (the spy's "Okay, I got it…" mail) | `47bee6fe2fe754b19edc3c0063ae46b496c8f0fd864fb726e690849b22e47168` |
| `data_leakage_autosummary_row453.bin` | 827 | type 2, not decoded | `b5e4407ab1babe9a509b6ffb531924b84e285338d3122fc383829fadacbbaa33` |
