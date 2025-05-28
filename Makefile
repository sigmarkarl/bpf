.PHONY: all build-linux build-linux-arm clean

BINARY_NAME=packet_sniffer
LINUX_BINARY=$(BINARY_NAME)_linux_amd64
LINUX_ARM_BINARY=$(BINARY_NAME)_linux_arm64

all: build-linux

# For cross-compilation from non-Linux OS
build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(LINUX_BINARY) .
	
# For cross-compilation from non-Linux OS
build-linux-arm:
	GOOS=linux GOARCH=arm64 go build -o $(LINUX_ARM_BINARY) .
	
clean:
	rm -f $(LINUX_BINARY)
	rm -f $(LINUX_ARM_BINARY)
