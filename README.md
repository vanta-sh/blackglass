# BlackGlass Scanner

A CLI tool developed by Vanta to detect telemetry on your system.

## Features

- Scans running processes for telemetry
- Checks installed software for telemetry components
- Examines Windows telemetry settings (Windows only)
- Analyzes network connections for telemetry endpoints
- Scans filesystem for telemetry-related files
- Exports results to JSON for further analysis

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/vanta-sh/blackglass-scanner.git
   cd blackglass-scanner
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Basic scan:
```
python blackglass_scanner.py
```

Quick scan (skips filesystem scan):
```
python blackglass_scanner.py --quick
```

## Output

The tool provides colored terminal output showing:
- Telemetry components detected on your system
- Windows telemetry settings (on Windows systems)

Results are also exported to a JSON file for further analysis.

## Warning

This tool is provided for educational and informational purposes only. Use responsibly and only on systems you own or have permission to scan. 