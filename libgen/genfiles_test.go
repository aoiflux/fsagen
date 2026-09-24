package libgen

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
)

func TestGenerateChromeHistory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "chrome_history_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	errChan := make(chan error, 1)

	generateChromeHistory(tempDir, errChan)

	if err := <-errChan; err != nil {
		t.Fatal(err)
	}

	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	var historyPath string
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".db" {
			historyPath = filepath.Join(tempDir, f.Name())
			break
		}
	}

	if historyPath == "" {
		t.Fatal("No history file generated")
	}

	db, err := sql.Open("sqlite", historyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tables := []string{"urls", "visits"}
	for _, table := range tables {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count)
		if err != nil {
			t.Errorf("Table %s verification failed: %v", table, err)
		}
		if count == 0 {
			t.Errorf("Table %s is empty", table)
		}
	}

	rows, err := db.Query("SELECT url, title, visit_count FROM urls")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	urlCount := 0
	for rows.Next() {
		var url, title string
		var visitCount int
		if err := rows.Scan(&url, &title, &visitCount); err != nil {
			t.Fatal(err)
		}
		if url == "" {
			t.Error("Empty URL found")
		}
		if title == "" {
			t.Error("Empty title found")
		}
		if visitCount <= 0 {
			t.Error("Invalid visit count")
		}
		urlCount++
	}

	if urlCount == 0 {
		t.Error("No URLs found in history")
	}
}

func TestGenerateFirefoxPlaces(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "firefox_places_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	errChan := make(chan error, 1)

	generateFirefoxPlaces(tempDir, errChan)

	if err := <-errChan; err != nil {
		t.Fatal(err)
	}

	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	var placesPath string
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".sqlite" {
			placesPath = filepath.Join(tempDir, f.Name())
			break
		}
	}

	if placesPath == "" {
		t.Fatal("No places.sqlite file generated")
	}

	db, err := sql.Open("sqlite", placesPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tables := []string{"moz_places", "moz_historyvisits"}
	for _, table := range tables {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count)
		if err != nil {
			t.Errorf("Table %s verification failed: %v", table, err)
		}
		if count == 0 {
			t.Errorf("Table %s is empty", table)
		}
	}

	rows, err := db.Query("SELECT url, title, visit_count FROM moz_places")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	placeCount := 0
	for rows.Next() {
		var url, title string
		var visitCount int
		if err := rows.Scan(&url, &title, &visitCount); err != nil {
			t.Fatal(err)
		}
		if url == "" {
			t.Error("Empty URL found")
		}
		if title == "" {
			t.Error("Empty title found")
		}
		if visitCount <= 0 {
			t.Error("Invalid visit count")
		}
		placeCount++
	}

	if placeCount == 0 {
		t.Error("No places found in database")
	}
}

func TestBrowserHistoryTimestamps(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "browser_timestamps_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	errChan := make(chan error, 2)

	generateChromeHistory(tempDir, errChan)
	generateFirefoxPlaces(tempDir, errChan)

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatal(err)
		}
	}

	checkTimestamps := func(db *sql.DB, table string, timeField string) error {
		var timestamp int64
		err := db.QueryRow("SELECT " + timeField + " FROM " + table + " LIMIT 1").Scan(&timestamp)
		if err != nil {
			return err
		}

		tm := time.Unix(timestamp, 0)
		now := time.Now()
		if tm.After(now) {
			return fmt.Errorf("Future timestamp found: %v", tm)
		}
		if tm.Before(now.AddDate(-1, 0, 0)) { // More than 1 year old
			return fmt.Errorf("Too old timestamp found: %v", tm)
		}
		return nil
	}

	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range files {
		path := filepath.Join(tempDir, f.Name())
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		switch filepath.Ext(f.Name()) {
		case ".db":
			if err := checkTimestamps(db, "urls", "last_visit_time"); err != nil {
				t.Errorf("Chrome timestamp check failed: %v", err)
			}
		case ".sqlite":
			if err := checkTimestamps(db, "moz_places", "last_visit_date"); err != nil {
				t.Errorf("Firefox timestamp check failed: %v", err)
			}
		}
	}
}
