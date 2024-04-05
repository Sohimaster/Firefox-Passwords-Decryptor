package recon

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type Port struct {
	Port        int
	Protocol    string
	ProcessName string
	ProcessId   int
}

func GetPortsInfo() ([]Port, error) {
	var cmd *exec.Cmd

	if runtime.GOOS == "darwin" {
		cmd = exec.Command("lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n")
	} else if runtime.GOOS == "linux" {
		cmd = exec.Command("sh", "-c", "sudo netstat -tulpen")
	} else {
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return parsePortInfo(string(output))
}

func parsePortInfo(output string) ([]Port, error) {
	var portInfoList []Port

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "LISTEN") {
			fields := strings.Fields(line)

			processName := fields[0]
			processID, _ := strconv.Atoi(fields[1])

			var protocol string
			if strings.Contains(line, "TCP") {
				protocol = "TCP"
			} else if strings.Contains(line, "UDP") {
				protocol = "UDP"
			}
			address := fields[len(fields)-2]
			port := parsePort(address)

			portInfoList = append(portInfoList, Port{
				Protocol:    protocol,
				ProcessId:   processID,
				ProcessName: processName,
				Port:        port,
			})
		}
	}

	return portInfoList, nil
}

func parsePort(address string) int {
	parts := strings.Split(address, ":")
	port, _ := strconv.Atoi(parts[len(parts)-1])

	return port
}
