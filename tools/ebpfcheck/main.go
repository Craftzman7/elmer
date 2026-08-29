//go:build linux

// ebpfcheck is a diagnostic: it loads elmer's eBPF programs and prints raw
// events for ~15 seconds so an operator can confirm the kernel, privileges,
// and tracepoints are working before relying on elmer start.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"elmer/internal/events"
	"elmer/internal/monitors/ebpf"
)

func main() {
	rt, err := ebpf.Load()
	if err != nil {
		fmt.Println("LOAD FAILED:", err)
		fmt.Println("(elmer will fall back to netlink/polling)")
		os.Exit(1)
	}
	defer rt.Close()
	fmt.Println("eBPF loaded OK — exec events will print below")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	out := make(chan events.Event, 256)
	go rt.Run(ctx, out)
	for {
		select {
		case ev := <-out:
			fmt.Println(ev.Summary())
			for k, v := range ev.Fields {
				fmt.Printf("    %-8s %s\n", k, v)
			}
		case <-ctx.Done():
			fmt.Println("done")
			return
		}
	}
}
