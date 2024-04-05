package recon

// #include <unistd.h>
import "C"

import (
	"os"
	"runtime"
)

type system struct {
	Hostname    string
	Os          string
	Arch        string
	CpusCount   int
	MemoryCount int
}

func GetSystemInfo() system {
	mem := int(C.sysconf(C._SC_PHYS_PAGES) * C.sysconf(C._SC_PAGE_SIZE))
	hostname, _ := os.Hostname()
	return system{
		Hostname:    hostname,
		Os:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		CpusCount:   runtime.NumCPU(),
		MemoryCount: mem / 1024 / 1024,
	}
}
