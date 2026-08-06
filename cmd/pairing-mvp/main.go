// pairing-mvp runs a disposable, loopback-only developer lab for EnvBank's
// real device-enrollment protocol. It intentionally accepts no config paths or
// production service addresses.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GeorgeQLe/envbank/internal/pairingmvp"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "pairing-mvp accepts no arguments; it always uses loopback and disposable storage")
		os.Exit(2)
	}
	lab, err := pairingmvp.NewLab()
	if err != nil {
		fmt.Fprintln(os.Stderr, "start pairing lab:", err)
		os.Exit(1)
	}
	defer lab.Close()
	ui, err := pairingmvp.StartUI(lab)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start pairing UI:", err)
		os.Exit(1)
	}
	defer ui.Close()
	fmt.Println("EnvBank disposable pairing lab:", ui.URL)
	fmt.Println("Press Ctrl-C to stop; temporary keys and SQLite storage are removed at shutdown.")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = ui.HTTP.Shutdown(ctx)
}
