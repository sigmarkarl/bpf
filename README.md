# BPF Packet Sniffer

A simple packet sniffer using BPF (Berkeley Packet Filter) in Go. This tool attaches a BPF filter to a raw socket to capture and analyze IP packets.

## Linux-Only Project

This project is designed for Linux systems only since BPF filtering is a Linux-specific feature. The code will not compile or run on non-Linux operating systems like macOS or Windows.

### Building

Use the provided Makefile to compile for Linux targets:

```bash
# Build for Linux x86_64
make build-linux

# Build for Linux ARM64 
make build-linux-arm

# Build both Linux targets
make all

# Clean compiled binaries
make clean
```

The resulting binaries will be:
- `packet_sniffer_linux_amd64` - For x86_64 Linux systems
- `packet_sniffer_linux_arm64` - For ARM64 Linux systems (e.g., Raspberry Pi)

### Cross-Compilation Note

While the code can be cross-compiled from macOS or Windows to Linux using the Makefile, the code itself is designed to run **only** on Linux systems. The BPF implementation relies on Linux-specific syscalls and socket operations.

#### Important for Linux Deployment
When deploying on Linux, you'll need to modify the file to use the full BPF implementation:

1. On your Linux machine, edit the `main.go` file
2. Uncomment the `attachRealBPFFilter` function
3. Replace the BPF filter implementation to use `syscall.SetsockoptSockFprog`
4. Recompile on the Linux machine with: `go build -o packet_sniffer main.go`

The cross-compiled version is set up to build successfully but some functionality is stubbed out.

### Running on Linux

Transfer the appropriate binary to your Linux system and run it as root:

```bash
sudo ./packet_sniffer_linux_amd64 eth0
```

Replace `eth0` with the network interface you want to monitor.

## Important Notes

- The program must be run as root (using `sudo`) on Linux to access raw sockets.
- BPF filtering is fully functional only on Linux systems.
- When cross-compiled from macOS, some functionality is stubbed until the program runs on an actual Linux system.

## Requirements

- Go 1.16 or later
- Root privileges on the Linux system where the program is executed
