// remnascope-awg-sensor watches the packets of one AmneziaWG interface inside a container and prints a short
// summary of the flows every minute. It is started as root only to open the packet socket in the container's
// network namespace; it then gives up root for good. It writes nothing to disk, keeps no packets, and prints
// only: the device's tunnel address, where it connected to, how many bytes each way, and a name for the
// destination when the packets said one in the open (TLS server name, HTTP Host, DNS answer).
//
// Output, one report per window:
//
//	W <container> <start unix> <end unix> <dropped packets> <flows left out>
//	F <device address> <protocol> <destination address> <port> <bytes up> <bytes down> <name> <name source> <began in this window: 1 or 0>
//	E
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Taminum/RemnaScope/internal/awgsensor"
)

const maxReported = 4000 // flows per window; the busiest come first, the rest are counted as left out

func main() {
	pid := flag.Int("pid", 0, "process id inside the container (its network namespace is used)")
	iface := flag.String("iface", "awg0", "interface name inside the container")
	container := flag.String("container", "", "container name, printed in every report")
	every := flag.Duration("interval", time.Minute, "length of a reporting window")
	sock := flag.String("out", "", "Unix socket to write the reports to (opened before root is given up); default is standard output")
	flag.Parse()
	if *pid <= 1 || *container == "" || *every < 5*time.Second || *every > time.Hour {
		fmt.Fprintln(os.Stderr, "remnascope-awg-sensor: -pid, -container and a sane -interval are required")
		os.Exit(2)
	}
	fd, err := awgsensor.OpenCapture(*pid, *iface)
	if err != nil {
		fmt.Fprintln(os.Stderr, "remnascope-awg-sensor:", err)
		os.Exit(1)
	}
	var dest io.Writer = os.Stdout
	if *sock != "" {
		c, err := net.Dial("unix", *sock)
		if err != nil {
			fmt.Fprintln(os.Stderr, "remnascope-awg-sensor: cannot reach the agent socket:", err)
			os.Exit(1)
		}
		defer c.Close()
		dest = c
	}
	if err := awgsensor.DropPrivileges(); err != nil {
		fmt.Fprintln(os.Stderr, "remnascope-awg-sensor: could not give up root:", err)
		os.Exit(1)
	}
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; close(stop) }()

	out := bufio.NewWriter(dest)
	agg := awgsensor.New()
	err = awgsensor.Read(fd, agg, *every, func(start, end time.Time, flows []awgsensor.Flow, dropped uint64) {
		left := 0
		if len(flows) > maxReported {
			left = len(flows) - maxReported
			flows = flows[:maxReported]
		}
		fmt.Fprintf(out, "W\t%s\t%d\t%d\t%d\t%d\n", *container, start.Unix(), end.Unix(), dropped, left)
		for _, f := range flows {
			started := 0
			if f.Started {
				started = 1
			}
			fmt.Fprintf(out, "F\t%s\t%d\t%s\t%d\t%d\t%d\t%s\t%s\t%d\n", f.Client, f.Proto, f.Remote, f.Port, f.Up, f.Down, f.Name, f.How, started)
		}
		fmt.Fprintln(out, "E")
		if out.Flush() != nil { // the agent went away: stop, systemd starts a fresh sensor which reconnects
			os.Exit(1)
		}
	}, stop)
	if err != nil {
		fmt.Fprintln(os.Stderr, "remnascope-awg-sensor:", err)
		os.Exit(1)
	}
}
