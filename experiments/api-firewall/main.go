package main
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type stats bpf bpf/filter.c

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)


func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach to 'lo' for local testing. Use 'eth0' or similar for production.
	ifaceName := "lo"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Attach the XDP program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DdosDetector,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP: %s", err)
	}
	defer l.Close()

	fmt.Printf("🔥 Firewall active on %s!\n", ifaceName)
	fmt.Println("Press Ctrl+C to stop and detach.")

	// Simple monitoring loop: Check the map for blocked IPs
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		for range ticker.C {
			var (
				key   uint32
				val   bpfStats
				iter  = objs.IpStats.Iterate()
			)
			fmt.Println("--- Active IP Watchlist ---")
			for iter.Next(&key, &val) {
				ip := make(net.IP, 4)
				ip[0] = byte(key)
				ip[1] = byte(key >> 8)
				ip[2] = byte(key >> 16)
				ip[3] = byte(key >> 24)
				
				status := "CLEAN"
				if val.Count > 100 {
					status = "DROPPING"
				}
				fmt.Printf("IP: %-15s Packets/sec: %-5d Status: %s\n", ip, val.Count, status)
			}
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}
