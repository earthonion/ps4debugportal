# PS4 Memory Debugger Web Interface

A full-featured web-based PS4 memory debugger with real-time monitoring, disassembly, and memory editing capabilities.

## Features

- **Memory Scanner**: Search for values in PS4 process memory with filtering
- **Memory Editor**: Read and write memory with hex viewer
- **Disassembler**: Disassemble x86_64 code at any address
- **Real-time Monitor**: Monitor memory addresses with live updates via WebSocket
- **Process Manager**: Connect to PS4 and select target process
- **Auto-discovery**: Automatically find PS4 on the network
## Screenshots
![alt text](https://github.com/earthonion/ps4debugportal/blob/main/screenshots/1.png?raw=true)
![alt text](https://github.com/earthonion/ps4debugportal/blob/main/screenshots/2.png?raw=true)
![alt text](https://github.com/earthonion/ps4debugportal/blob/main/screenshots/3.png?raw=true)
![alt text](https://github.com/earthonion/ps4debugportal/blob/main/screenshots/4.png?raw=true)
## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Make sure your PS4 is running ps4debug payload

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to:
```
http://localhost:5001
```

## Usage

### Connecting to PS4
1. Enter your PS4's IP address or leave blank for auto-discovery
2. Click "Connect"
3. Select the target process from the dropdown

### Memory Scanning
1. Enter the value you're looking for
2. Select the data type (Float, Int32, Double)
3. Set tolerance for approximate matches
4. Click "New Scan" to search all memory
5. Use "Filter" to narrow down results with a new value

### Memory Editing
1. Enter a memory address in hex format
2. Read memory to view hex dump
3. Write new values with type selection

### Disassembler
1. Enter the address to disassemble
2. Specify number of bytes to disassemble
3. View x86_64 assembly instructions

### Real-time Monitoring
1. Enter an address to monitor
2. Select data type
3. Set update interval in milliseconds
4. Watch values update in real-time

### Debugger
1. set a breakpoint
2. look at the registers when it hits
3. note: you may need to run as root to listen on port 755
4. also, it defaults to auto resume on hit. it doesnt pause. can be changed in source code

## API Endpoints

- `POST /api/connect` - Connect to PS4
- `GET /api/processes` - Get process list
- `POST /api/select_process` - Select target process
- `POST /api/scan` - Scan memory for values
- `POST /api/filter_scan` - Filter previous scan results
- `POST /api/read` - Read memory at address
- `POST /api/write` - Write memory at address
- `POST /api/disassemble` - Disassemble code

## WebSocket Events

- `monitor_address` - Start monitoring an address
- `monitor_update` - Receive real-time value updates

## Security Warning

This tool provides direct memory access to PS4 processes. Use with caution and only on your own console for debugging purposes.

## Requirements

- PS4 running ps4debug payload
- Python 3.8+
- Network connectivity between PC and PS4
