package main

import (
	"encoding/json"
	"flag"
	"fmt"
	browser "github.com/sohimaster/Firefox-Passwords-Decryptor/recon/browser/firefox"
	"path/filepath"

	"github.com/sohimaster/Firefox-Passwords-Decryptor/recon"
)

func main() {
	// Define command-line flags
	sysInfoFlag := flag.Bool("sysinfo", false, "Get system information")
	portsInfoFlag := flag.Bool("ports", false, "Get ports information")
	devicesInfoFlag := flag.Bool("devices", false, "Get devices information")
	historyFlag := flag.Bool("history", false, "Get Firefox browsing history")
	passwordsFlag := flag.Bool("passwords", false, "Get Firefox passwords")

	// Parse the flags
	flag.Parse()

	if *sysInfoFlag {
		systemInfo, _ := json.MarshalIndent(recon.GetSystemInfo(), "", "  ")
		fmt.Println("System info: ", string(systemInfo))
	}

	if *portsInfoFlag {
		ports, err := recon.GetPortsInfo()
		if err != nil {
			fmt.Println(err)
			return
		}
		portsInfo, _ := json.MarshalIndent(ports, "", "  ")
		fmt.Println("Ports info: ", string(portsInfo))
	}

	if *devicesInfoFlag {
		devicesInfo := recon.GetDevicesInfo()
		devicesInfoJson, _ := json.MarshalIndent(devicesInfo, "", "  ")
		fmt.Println("Devices info: ", string(devicesInfoJson))
	}

	if *historyFlag || *passwordsFlag {
		firefoxProfilePath, err := browser.GetProfilePath()
		if err != nil {
			fmt.Println(err)
			return
		} else {
			fmt.Println("Firefox profile path: ", firefoxProfilePath)
		}

		if *historyFlag {
			dbPath := filepath.Join(string(firefoxProfilePath), browser.FirefoxDBFile)
			browsingHistory, err := browser.GetBrowsingHistoryTempDB(dbPath, 10) // Adjusted for compatibility
			if err != nil {
				fmt.Println("Error on retrieving history", err)
			}
			browsingHistoryJson, _ := json.MarshalIndent(browsingHistory, "", "  ")
			fmt.Println("Browsing history: ", string(browsingHistoryJson))
		}

		if *passwordsFlag {
			logins, err := browser.GetPasswords(firefoxProfilePath)
			if err != nil {
				fmt.Println(err)
				return
			}
			loginsText, _ := json.MarshalIndent(logins, "", "  ")
			fmt.Println("Logins: ", string(loginsText))
		}
	}
}
