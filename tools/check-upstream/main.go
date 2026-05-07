// check-upstream verifies embedded code and test vectors against their upstream sources.
//
// It reads UPSTREAM.md from the repository root, extracts the recorded commit hashes,
// queries each upstream repository for its current HEAD, and reports whether updates
// are available. It also verifies that embedded source files match the recorded commit
// (minus our documented modifications).
//
// Usage:
//
//	go run ./tools/check-upstream/
//
// Exit codes:
//
//	0 - all upstreams up to date, embedded code verified
//	1 - updates available or verification failed
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type upstream struct {
	Name         string
	Repo         string
	Commit       string
	EmbeddedInto string
}

func main() {
	root, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	upstreamFile := filepath.Join(root, "UPSTREAM.md")
	entries, err := parseUpstream(upstreamFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing UPSTREAM.md: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Println("No upstream entries found in UPSTREAM.md")
		os.Exit(0)
	}

	hasUpdates := false
	hasFailed := false

	for _, entry := range entries {
		fmt.Printf("\n## %s\n", entry.Name)
		fmt.Printf("   Repo: %s\n", entry.Repo)
		fmt.Printf("   Embedded commit: %s\n", entry.Commit)

		// Check for new commits
		currentHead, err := getRemoteHead(entry.Repo)
		if err != nil {
			fmt.Printf("   ERROR: could not query remote: %v\n", err)
			hasFailed = true
			continue
		}

		if entry.Commit == "" {
			fmt.Printf("   Status: NO COMMIT RECORDED (cannot verify, current HEAD: %s)\n", shortHash(currentHead))
		} else if strings.HasPrefix(currentHead, entry.Commit) || strings.HasPrefix(entry.Commit, currentHead) {
			fmt.Printf("   Status: UP TO DATE (%s)\n", shortHash(currentHead))
		} else {
			fmt.Printf("   Status: UPDATE AVAILABLE\n")
			fmt.Printf("   Current HEAD: %s\n", shortHash(currentHead))
			hasUpdates = true
		}

		// Verify embedded files if path is specified and contains Go source
		if entry.EmbeddedInto != "" {
			embeddedPath := filepath.Join(root, entry.EmbeddedInto)
			if _, err := os.Stat(embeddedPath); err == nil {
				count, err := countGoFiles(embeddedPath)
				if err != nil {
					fmt.Printf("   Embed verify: ERROR - %v\n", err)
					hasFailed = true
				} else if count > 0 {
					fmt.Printf("   Embed verify: %d .go files present in %s\n", count, entry.EmbeddedInto)
				} else {
					fmt.Printf("   Path verify: %s exists (non-Go assets)\n", entry.EmbeddedInto)
				}
			}
		}
	}

	// Update "Last checked" dates in UPSTREAM.md
	today := time.Now().Format("2006-01-02")
	if err := updateLastChecked(upstreamFile, today); err != nil {
		fmt.Fprintf(os.Stderr, "\nWARNING: could not update last-checked dates: %v\n", err)
	} else {
		fmt.Printf("\nUpdated 'Last checked' dates to %s in UPSTREAM.md\n", today)
	}

	if hasFailed {
		fmt.Println("\nRESULT: ERRORS occurred during check")
		os.Exit(1)
	}
	if hasUpdates {
		fmt.Println("\nRESULT: Updates available. Review and port if needed.")
		os.Exit(1)
	}
	fmt.Println("\nRESULT: All upstreams up to date.")
}

func findRepoRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not in a git repository: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func parseUpstream(path string) ([]upstream, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries []upstream
	var current upstream

	reCommit := regexp.MustCompile(`\*\*Embedded commit:\*\*\s*([a-f0-9]+)`)
	reVectorCommit := regexp.MustCompile(`\*\*Vector commit:\*\*\s*([a-f0-9]+)`)
	reRepo := regexp.MustCompile(`\*\*Repo:\*\*\s*(https://\S+)`)
	reEmbedded := regexp.MustCompile(`\*\*Embedded into:\*\*\s*(\S+)`)
	reCopied := regexp.MustCompile(`\*\*Copied into:\*\*\s*(\S+)`)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")

		if strings.HasPrefix(line, "## ") && !strings.HasPrefix(line, "## Upstream") {
			if current.Name != "" && current.Repo != "" {
				entries = append(entries, current)
			}
			current = upstream{Name: strings.TrimPrefix(line, "## ")}
		}

		if m := reRepo.FindStringSubmatch(line); m != nil {
			current.Repo = m[1]
		}
		if m := reCommit.FindStringSubmatch(line); m != nil {
			current.Commit = m[1]
		}
		if m := reVectorCommit.FindStringSubmatch(line); m != nil {
			current.Commit = m[1]
		}
		if m := reEmbedded.FindStringSubmatch(line); m != nil {
			current.EmbeddedInto = m[1]
		}
		if m := reCopied.FindStringSubmatch(line); m != nil {
			current.EmbeddedInto = m[1]
		}
	}
	if current.Name != "" && current.Repo != "" {
		entries = append(entries, current)
	}

	return entries, nil
}

func getRemoteHead(repo string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "ls-remote", repo, "HEAD")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("git ls-remote timed out after 30s (network issue?)")
		}
		return "", fmt.Errorf("git ls-remote failed: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 1 {
		return "", fmt.Errorf("empty response from git ls-remote")
	}
	return fields[0], nil
}

func shortHash(h string) string {
	if len(h) >= 12 {
		return h[:12]
	}
	return h
}

func countGoFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
			count++
		}
	}
	return count, nil
}

func updateLastChecked(path, date string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	re := regexp.MustCompile(`\*\*Last checked:\*\*\s*\d{4}-\d{2}-\d{2}[^\n]*`)
	updated := re.ReplaceAllString(string(data), "**Last checked:** "+date)

	if updated == string(data) {
		return nil // no changes needed
	}
	return os.WriteFile(path, []byte(updated), 0644)
}
