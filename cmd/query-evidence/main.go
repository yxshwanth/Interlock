package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/yxshwanth/Interlock/internal/engine"
)

func main() {
	dbPath := flag.String("db", "evidence.db", "path to SQLite evidence database")
	session := flag.String("session", "", "filter by session_id")
	verdict := flag.String("verdict", "", "filter by verdict (EXFIL | SUSPICIOUS)")
	pod := flag.String("pod", "", "filter by pod_name")
	limit := flag.Int("limit", 100, "max records (default 100, max 1000)")
	flag.Parse()

	sink, err := engine.NewSQLiteEvidenceSink(*dbPath, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query-evidence: open: %v\n", err)
		os.Exit(2)
	}
	defer sink.Close()

	recs, err := sink.Query(context.Background(), engine.EvidenceQuery{
		SessionID: *session,
		Verdict:   *verdict,
		PodName:   *pod,
		Limit:     *limit,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "query-evidence: query: %v\n", err)
		os.Exit(2)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(recs); err != nil {
		fmt.Fprintf(os.Stderr, "query-evidence: encode: %v\n", err)
		os.Exit(2)
	}
}
