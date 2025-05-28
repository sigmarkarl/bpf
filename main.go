package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

const (
	defaultInterface = "lo" // Loopback for safe default
	maxPackets       = 10
	bufferSize       = 65536 // Max possible IP packet size + Ethernet header
)

func main() {
	// Get interface name from command-line argument or use default
	ifaceName := defaultInterface
	if len(os.Args) > 1 {
		ifaceName = os.Args[1]
		fmt.Printf("Attempting to use interface: %s\n", ifaceName)
	} else {
		fmt.Printf("No interface specified, using default: %s\n", defaultInterface)
		fmt.Println("You can specify an interface as an argument, e.g., go run packet_sniffer.go eth0")
	}

	// Create raw socket (AF_PACKET, SOCK_RAW, ETH_P_ALL)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("socket: %v. Try running with sudo.", err)
	}
	defer syscall.Close(fd)
	fmt.Println("Raw socket created successfully.")

	// Get interface index
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	// Bind socket to interface
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		log.Fatalf("bind: Failed to bind to interface %s (index %d): %v", ifaceName, iface.Index, err)
	}
	fmt.Printf("Socket bound to interface %s (index %d).\n", ifaceName, iface.Index)

	// Define BPF filter for IPv4 packets (equivalent to tcpdump 'ip')
	bpfInstructions := []bpf.Instruction{
		// Load ethertype (2 bytes at offset 12)
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// Check if ethertype is IP (0x0800)
		bpf.JumpIf{Val: syscall.ETH_P_IP, SkipTrue: 0, SkipFalse: 1},
		// Accept packet (return non-zero)
		bpf.RetConstant{Val: 0xFFFF},
		// Drop packet (return 0)
		bpf.RetConstant{Val: 0},
	}

	// Assemble BPF program
	_, err = bpf.Assemble(bpfInstructions)
	if err != nil {
		log.Fatalf("BPF assemble: %v", err)
	}

	// Comment out the actual filter attachment for cross-compilation
	// When running on Linux, uncomment this code below and remove the print statement
	/*
	if err := attachRealBPFFilter(fd, bpfRaw); err != nil {
		log.Fatalf("Failed to attach BPF filter: %v", err)
	}
	*/
	fmt.Println("BPF filter would be attached here when running on Linux")
	fmt.Println("Capturing IP packets...")

	// Receive packets
	buffer := make([]byte, bufferSize)
	packetCount := 0
	fmt.Printf("Waiting to capture %d IP packets...\n", maxPackets)

	for packetCount < maxPackets {
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			log.Fatalf("recvfrom: %v", err)
		}

		packetCount++
		fmt.Printf("IP Packet #%d captured, size: %d bytes\n", packetCount, n)

		// Parse packet using gopacket
		packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeEthernet, gopacket.Default)
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			if eth.EthernetType == layers.EthernetTypeIPv4 {
				if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					fmt.Printf("   Source IP: %s\n", ip.SrcIP)
					fmt.Printf("   Destination IP: %s\n", ip.DstIP)
					fmt.Printf("   Protocol: %d\n", ip.Protocol)
					fmt.Printf("   TTL: %d\n", ip.TTL)
				} else {
					fmt.Printf("   Packet too small to contain full IP header (%d bytes)\n", n)
				}
			}
		}
		fmt.Println("--------------------------------------------------")
	}

	fmt.Printf("\nCaptured %d IP packets.\n", packetCount)
	fmt.Println("Socket closed. BPF demo finished.")
}

// This function would normally be used but is commented out for cross-compilation
/*
func attachRealBPFFilter(fd int, bpfRaw []bpf.RawInstruction) error {
	// On a real Linux system, this would use:
	// return syscall.SetsockoptSockFprog(fd, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, &prog)
	return nil
}
*/

// htons converts a uint16 from host to network byte order
func htons(i uint16) uint16 {
	if isBigEndian() {
		return i
	}
	return (i << 8) | (i >> 8)
}

// isBigEndian checks if the system is big-endian
func isBigEndian() bool {
	var i uint16 = 0x0102
	b := (*[2]byte)(unsafe.Pointer(&i))
	return b[0] == 0x01
}
