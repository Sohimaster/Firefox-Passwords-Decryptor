package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"

	browser "github.com/sohimaster/Firefox-Passwords-Decryptor/recon/browser/firefox"
)

func main() {
	// Define command-line flags
	historyFlag := flag.Bool("history", false, "Get Firefox browsing history")
	passwordsFlag := flag.Bool("passwords", false, "Get Firefox passwords")

	// Parse the flags
	flag.Parse()

	// If no flags are provided, default to passwords
	if !*historyFlag && !*passwordsFlag {
		*passwordsFlag = true
	}

	if *historyFlag || *passwordsFlag {
		firefoxProfilePath, err := browser.GetProfilePath()
		if err != nil {
			fmt.Println("Error finding Firefox profile:", err)
			return
		}
		fmt.Println("Firefox profile path:", firefoxProfilePath)

		if *historyFlag {
			dbPath := filepath.Join(string(firefoxProfilePath), browser.FirefoxDBFile)
			browsingHistory, err := browser.GetBrowsingHistoryTempDB(dbPath, 10)
			if err != nil {
				fmt.Println("Error retrieving history:", err)
				return
			}
			browsingHistoryJson, _ := json.MarshalIndent(browsingHistory, "", "  ")
			fmt.Println("Browsing history:", string(browsingHistoryJson))
		}

		if *passwordsFlag {
			credentials, err := browser.ExtractPasswords(string(firefoxProfilePath))
			if err != nil {
				fmt.Println("Error retrieving passwords:", err)
				return
			}
			credentialsJSON, _ := json.MarshalIndent(credentials, "", "  ")
			fmt.Println("Saved passwords:", string(credentialsJSON))
		}
	}
}
