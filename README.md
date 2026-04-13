# WerWolf

<p align="center">
  <img src="logo.png" alt="WerWolf" width="300" height="300">
</p>

**In-memory BOF implementation of the Silent Process Exit LSASS dump technique**

WerWolf takes the `RtlReportSilentProcessExit` technique (originally presented by Asaf Gilboa at DEF CON 30) and executes it as an in-memory Beacon Object File via a custom Python COFF loader. No executable on disk. No PowerShell. No script block logging. No AMSI.

For the full technical deep-dive, research story, and how this improves on existing implementations, read the companion article on Medium: **[WerWolf: Taking Silent Process Exit from PowerShell Script to In-Memory BOF](#)** *(link coming soon)*

## Usage

```bash
# Just run it (requires admin on Windows)
python main.py

# Verbose mode
python main.py -v
```

That's it. WerWolf automatically loads and executes the BOF. No arguments needed.

## Requirements

- Python 3.8+
- Windows (tested on Windows 10/11 and Server 2016+)
- Administrator privileges

## Output

The dump is written to `C:\Windows\Temp\`. Parse it offline:

```bash
pypykatz lsa minidump C:\Windows\Temp\lsass.exe_*.dmp
```

## Project Structure

```
WerWolf/
├── main.py              # Entry point - just run it
├── loader/
│   ├── parser.py        # COFF format parser
│   └── loader.py        # In-memory loader & executor
└── bofs/
    ├── include/
    │   └── beacon.h     # BOF API header
    └── wer_execute.o    # The WerWolf BOF (precompiled)
```

## Prior Art

- Asaf Gilboa - "LSASS Shtinkering" (DEF CON 30) - original technique discovery
- [deepinstinct/LsassSilentProcessExit](https://github.com/deepinstinct/LsassSilentProcessExit) - C implementation
- [CompassSecurity/PowerLsassSilentProcessExit](https://github.com/CompassSecurity/PowerLsassSilentProcessExit) - PowerShell implementation

WerWolf's contribution is the **delivery mechanism**: executing the technique as an in-memory BOF, avoiding the disk artifacts and script logging that the existing tools create.

## MITRE ATT&CK

| Technique | ID |
|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 |
| Modify Registry | T1112 |
| Signed Binary Proxy Execution | T1218 |

## Disclaimer

For authorized security testing and research only. Obtain written authorization before testing on systems you do not own.

## License

MIT
