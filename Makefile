.PHONY: all build-linux build-linux-arm clean run-tc run-tc-drop

BINARY_NAME=packet_sniffer
LINUX_BINARY=$(BINARY_NAME)_linux_amd64
LINUX_ARM_BINARY=$(BINARY_NAME)_linux_arm64

all: build-linux build-linux-arm

# For cross-compilation from non-Linux OS
build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(LINUX_BINARY) .
	
# For cross-compilation from non-Linux OS
build-linux-arm:
	GOOS=linux GOARCH=arm64 go build -o $(LINUX_ARM_BINARY) .
	
clean:
	rm -f $(LINUX_BINARY)
	rm -f $(LINUX_ARM_BINARY)

# Run with TC filters on eth0 (example, requires Linux and root)
run-tc:
	sudo ./$(LINUX_BINARY) -i eth0 -tc -n 20

# Run with TC filters in drop mode for TCP traffic (port 80)
run-tc-drop:
	sudo ./$(LINUX_BINARY) -i eth0 -tc -action drop -match "ip protocol 6 0xff" -n 20

# Run with TC filters for specific IP match (example for 192.168.1.1)
run-tc-ip:
	sudo ./$(LINUX_BINARY) -i eth0 -tc -match "ip src 192.168.1.1/32" -n 20
