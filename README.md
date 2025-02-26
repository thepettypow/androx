**Androx** is a powerful, Go-based tool designed for bug bounty hunters to automate the analysis of Android applications. It extracts critical data from APKs (source code, device storage, traffic), parses it for secrets and endpoints, and integrates professional tools like MobSF and JADX to uncover vulnerabilities. Whether you're hunting XSS, IDOR, SQLi, or access control flaws, Androx streamlines the process for any Android app in a bug bounty program.

## Features
- **Unified Workflow:** Decompile APKs, extract device data, capture traffic, and parse results in one tool.
- **Scalable:** Multi-threaded parsing for large APKs, configurable via CLI flags.
- **Professional Integration:** Uses MobSF for vulnerability scanning and JADX for decompilation.
- **Output:** Generates actionable files (secrets, endpoints, logs) for bug hunting.
- **Cross-Platform:** Runs on Linux, macOS, and Windows with Go’s single-binary ease.

## Installation

### Prerequisites
Ensure the following tools are installed before using Androx:

1. **Go** (1.18+):  
   - Linux: `sudo apt install golang`
   - macOS: `brew install go`
   - Windows: Download from [golang.org](https://golang.org/dl/)

2. **JADX**: For APK decompilation.  
   - Download from [GitHub](https://github.com/skylot/jadx/releases) and add `jadx/bin` to your PATH.
   - Example: `sudo ln -s /path/to/jadx/bin/jadx /usr/local/bin/jadx`

3. **MobSF**: For static analysis (Docker required).  
   - Install Docker: [docker.com](https://docs.docker.com/get-docker/)
   - Pull MobSF: `docker pull opensecurity/mobile-security-framework-mobsf`

4. **ADB**: For device data extraction (rooted device/emulator recommended).  
   - Linux: `sudo apt install android-tools-adb`
   - macOS: `brew install android-platform-tools`
   - Windows: Install via [Android SDK](https://developer.android.com/studio#downloads)

5. **mitmproxy** (optional): For traffic capture.  
   - Install: `pip install mitmproxy`

### Build Androx
1. Clone the repository:
   ```bash
   git clone https://github.com/thepettypow/Androx.git
   cd Androx
   ```
2. Build the binary:
   ```bash
   go build -o Androx Androx.go
   ```
3. (Optional) Move to PATH:
   ```bash
   sudo mv Androx /usr/local/bin/
   ```

## Usage

Androx accepts various command-line flags to customize its behavior. Here are some common examples:

### Basic Analysis
Decompile an APK, run MobSF, extract device data, and parse results:
```bash
Androx -a netflix.apk -p com.netflix.mediaclient
```
- Output: `com.netflix.mediaclient_output/` with decompiled code, MobSF report, device data, secrets, and endpoints.

### Verbose Mode with Custom Output
See real-time logs and specify an output directory:
```bash
Androx -a target.apk -p com.target.app -o my_analysis -v
```

### Traffic Capture
Capture app traffic with mitmproxy (run the app manually while this executes):
```bash
Androx -a target.apk -p com.target.app -t
```

### Custom Device Directory and Threads
Adjust device data path and parsing concurrency:
```bash
Androx -a target.apk -p com.target.app -d /custom/data/path -n 10
```

### Skip MobSF
Run without static analysis:
```bash
Androx -a target.apk -p com.target.app -m=false
```

### Full Options
```bash
Androx -h
```
Output:
```
Usage: Androx -a <apk> -p <package> [options]
  -a, --apk string         Path to APK file (required)
  -d, --device-dir string  Device data directory (default: /data/data/<package>)
  -m, --mobsf              Run MobSF analysis (default true)
  -n, --threads int        Number of parsing threads (default 5)
  -o, --output string      Output directory (default: <package>_output)
  -p, --package string     App package name (required)
  -t, --traffic            Capture traffic with mitmproxy
  -v, --verbose            Verbose output
```

## Output Structure
After running, the output directory contains:
- `decompiled/`: Source code from JADX (Java/Kotlin).
- `mobsf_report.txt`: MobSF vulnerability report (if enabled).
- `traffic.mitm`: Traffic capture file (if `-t` used).
- `databases/`, `shared_prefs/`, `files/`: Extracted device data.
- `secrets.txt`: API keys, tokens, secrets found in the app.
- `endpoints.txt`: URLs extracted from code and data.
- `hunter.log`: Detailed execution log.

## How to Use for Bug Bounty Hunting
1. **Obtain APK**: Download from a source like [APKPure](https://apkpure.com) or pull from a device:
   ```bash
   adb shell pm path com.netflix.mediaclient
   adb pull /data/app/.../base.apk netflix.apk
   ```
2. **Run Androx**: Analyze the APK:
   ```bash
   Androx -a netflix.apk -p com.netflix.mediaclient -v -t
   ```
3. **Hunt Bugs**:
   - **XSS**: Check `endpoints.txt` for WebView-related URLs, fuzz with XSS payloads.
   - **IDOR**: Look for numeric IDs in `endpoints.txt`, test with enumeration tools.
   - **SQLi**: Inspect `databases/` and `endpoints.txt` for injectable inputs.
   - **Open Redirects**: Test redirect params in `endpoints.txt`.
   - **Access Control**: Use `secrets.txt` tokens to test unauthorized API access.

## Notes
- **Root Access**: Device data extraction requires a rooted device/emulator (e.g., via Magisk).
- **Traffic Capture**: Run the app manually while mitmproxy is active, then stop with Ctrl+C.
- **Scope**: Always respect the bounty program’s scope (e.g., `*.netflix.com`).

## Contributing
We welcome contributions! To contribute:
1. Fork the repo and create a branch: `git checkout -b feature-name`.
2. Make changes and test thoroughly.
3. Submit a PR with a clear description of your changes.

Ideas for enhancements:
- Add Frida hooking for dynamic analysis.
- Support custom regex patterns for parsing.
- Integrate automated vuln testing (e.g., XSS fuzzing).


## License
MIT License. See [LICENSE](LICENSE) for more information.

## Acknowledgments
- Inspired by tools like MobSF, JADX, and the bug bounty community.
- Built with ❤️ by Petty Pow for hunters everywhere.

Happy hunting! 🚀
