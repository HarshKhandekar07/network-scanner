# Network Scanner Utility

A lightweight, multi-threaded **Network Scanner** application built with Python. It features a modern dark-themed Graphical User Interface (GUI) powered by Tkinter, allowing users to scan local subnets, resolve hostnames, map MAC address manufacturers/vendors, and export results directly to CSV.

---

## Features

### Intermediate Features
- **Device Count**: Tracks and displays the total number of active hosts discovered on the subnet.
- **Hostname Resolution**: Resolves target IP addresses to their human-readable hostnames via reverse DNS lookups.
- **Export Scan Results to CSV**: Saves lists of active devices including IP, MAC address, hostname, and vendor to a local file.
- **Display Vendor Information**: Correlates MAC addresses against an extensive OUI mapping dictionary (offline and online fallback) to display hardware manufacturers.
- **Graphical User Interface (GUI)**: Offers a beautiful dark-mode interface with flat styling, card views, and real-time progress indicators.
- **Multi-threaded Scanning**: Pings target IPs in parallel using a Python `ThreadPoolExecutor` to perform fast network scans.

### Advanced Features (Planned/Iterative)
- Port scanning and service detection.
- Passive/active OS fingerprinting.
- Flask-based web-accessible dashboard.
- Network topology graph visualization.
- Local SQLite database persistent storage.
- Scheduled network scans.
- Real-time alert notifications for new network joins.

---

## Project Structure

```
network-scanner/
├── devices.csv          # Exported scan records (dynamically generated)
├── main.py             # Tkinter GUI controller and application entry point
├── README.md           # Project documentation
├── requirements.txt    # Library dependency configurations
├── scanner.py          # Multithreaded IP pinging, MAC resolution, and DNS resolver
└── utils.py            # Local MAC OUI data, normalizer, and CSV exporter
```

---

## Requirements

- **Python 3.6+**
- **Tkinter** (built-in with Python on Windows/macOS. For Linux, install via `sudo apt-get install python3-tk`)

---

## Running the Application

Navigate to the project directory and launch the main controller script:

```bash
python3 main.py
```

### Usage Instructions
1. The application will auto-detect your local IPv4 address and populate a default scan target subnet (e.g., `192.168.1.0/24`).
2. You can customize the scanning range using CIDR notation (e.g. `10.0.0.0/24`) or ranges (e.g. `192.168.1.1-150`).
3. Click **Start Scan** to begin. The progress bar and status card will update in real-time.
4. Active hosts will start populating the table immediately as they are detected.
5. Click **Export CSV** to save the results to a file of your choice.
