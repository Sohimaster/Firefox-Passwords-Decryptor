package browser

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

const FirefoxDBFile = "places.sqlite"

type HistoryRow struct {
	ID         int
	URL        string
	Title      sql.NullString
	VisitCount int
	LastVisit  int64
}

func createTempFileCopy(filePath string) (string, error) {
	location := filepath.Dir(filePath)
	fileName := filepath.Base(filePath)

	// Read the original file
	srcFile, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer srcFile.Close()

	// Read the content of the original file into a byte slice
	srcFileContent, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	// Create a temporary file for the copy
	tempFile, err := os.CreateTemp(location, "*"+fileName)
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	// Write the content from the original file to the temporary file
	_, err = tempFile.Write(srcFileContent)
	if err != nil {
		return "", err
	}

	// Return the path to the temporary file
	return tempFile.Name(), nil
}

func cleanTempFiles(dbPath string) {
	filename := filepath.Base(dbPath)
	filenameNoExt := filepath.Base(filename)[0 : len(filename)-len(filepath.Ext(filename))]
	tempFiles, _ := filepath.Glob(filepath.Join(filepath.Dir(dbPath), filenameNoExt) + "*")
	for _, tempFile := range tempFiles {
		os.Remove(tempFile)
	}
}

func GetBrowsingHistoryTempDB(dbPath string, limit int) ([]*HistoryRow, error) {
	path, err := createTempFileCopy(dbPath)
	if err != nil {
		return nil, err
	}

	defer cleanTempFiles(path)

	browsingHistory, err := GetBrowsingHistory(path, limit)
	if err != nil {
		return nil, err
	}
	return browsingHistory, nil
}

func GetBrowsingHistory(dbPath string, limit int) ([]*HistoryRow, error) {
	var history []*HistoryRow

	fmt.Println("Db path: ", dbPath)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Println("Error opening db: ", err)
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT %d", limit)
	if err != nil {
		fmt.Println("Error querying db: ", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var row HistoryRow
		err = rows.Scan(&row.ID, &row.URL, &row.Title, &row.VisitCount, &row.LastVisit)
		if err != nil {
			return nil, err
		}
		history = append(history, &row)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return history, nil
}
