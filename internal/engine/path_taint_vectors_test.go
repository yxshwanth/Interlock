// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

type sensitivePathVector struct {
	Path     string   `json:"path"`
	Prefixes []string `json:"prefixes"`
	Result   bool     `json:"result"`
}

// extractPathsVector paths are sorted: the Go walk visits map keys in random
// order, so only the set of paths is part of the contract.
type extractPathsVector struct {
	ArgsJSON string   `json:"args_json"`
	Paths    []string `json:"paths"`
}

type pathTaintVector struct {
	Content string             `json:"content"`
	Path    string             `json:"path"`
	Source  string             `json:"source"`
	Seq     uint64             `json:"seq"`
	Tainted []pathTaintedValue `json:"tainted"`
}

type pathTaintedValue struct {
	ValueHex string   `json:"value_hex"`
	Hash     string   `json:"hash"`
	Preview  string   `json:"preview"`
	Forms    []string `json:"forms"`
	Source   string   `json:"source"`
	Seq      uint64   `json:"seq"`
}

type pathTaintVectorFile struct {
	SensitivePaths []sensitivePathVector `json:"sensitive_paths"`
	ExtractPaths   []extractPathsVector  `json:"extract_paths"`
	Taint          []pathTaintVector     `json:"taint"`
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func pathTaintVectors() pathTaintVectorFile {
	var out pathTaintVectorFile

	prefixes := []string{"/etc/secrets/", "/home/alice/.ssh"}
	for _, c := range []struct {
		path     string
		prefixes []string
	}{
		{"/data/wallet.p12", nil},
		{"/data/cert.pfx", nil},
		{"/data/vault.kdbx", nil},
		{"/data/report.xlsx", nil},
		{"/data/report.xlsm", nil},
		{"/data/report.xls", nil},
		{"/data/server.pem", nil},
		{"/data/server.key", nil},
		{"/data/server.crt", nil},
		{"/data/server.cer", nil},
		{"/data/store.jks", nil},
		{"/data/notes.txt", nil},
		{"/data/keyboard", nil},
		{"/home/bob/credentials", nil},
		{"/home/bob/.ssh/id_rsa", nil},
		{"/home/bob/.ssh/id_dsa", nil},
		{"/home/bob/.ssh/id_ecdsa", nil},
		{"/home/bob/.ssh/id_ed25519", nil},
		{"/srv/app/secrets.yaml", nil},
		{"/home/bob/.kube/kubeconfig", nil},
		{"/home/bob/.aws", nil},
		{"/srv/service-account.json", nil},
		{"/credentials/readme.txt", nil},
		{"/secrets/readme.txt", nil},
		{"/etc/secrets/db_password", prefixes},
		{"/etc/secrets", prefixes},
		{"/etc/other/db_password", prefixes},
		{"/home/alice/.ssh/config", prefixes},
		{"/home/alice/docs/a.txt", prefixes},
		{"/ETC/secrets/db_password", prefixes},
		{"etc/secrets/db_password", prefixes},
		{"/etc/secrets/db_password", []string{""}},
		{"/DATA/SERVER.PEM", nil},
		{"/home/bob/Credentials", nil},
		{"/home/bob/ID_RSA", nil},
		{"/data/../etc/secrets/x", prefixes},
		{"/data/../data/server.key", nil},
		{"/etc/secrets/../public/x.txt", prefixes},
		{"/data/credentials/../x.txt", nil},
		{"id_rsa", nil},
		{"./server.pem", nil},
		{"data/readme.md", nil},
		{"  /data/server.pem  ", nil},
		{"  /etc/secrets/x", prefixes},
		{"", nil},
		{"", prefixes},
		{"   ", nil},
		{"/", nil},
	} {
		out.SensitivePaths = append(out.SensitivePaths, sensitivePathVector{
			Path: c.path, Prefixes: nonNil(c.prefixes), Result: IsSensitiveResourcePath(c.path, c.prefixes),
		})
	}

	for _, args := range []string{
		``,
		`not json`,
		`null`,
		`[]`,
		`{}`,
		`{"path":"/data/a.txt"}`,
		`{"PATH":"/data/a.txt"}`,
		`{"File":"plain"}`,
		`{"filepath":"x","file_path":"y","excel_file":"z","filename":"w"}`,
		`{"source":"a","target":"b"}`,
		`{"path":"  "}`,
		`{"path":""}`,
		`{"outer":{"inner":{"path":"/deep/a.txt"}}}`,
		`{"files":[{"path":"a"},{"path":"b"}]}`,
		`{"path":["a","b"]}`,
		`{"path":[["a"],["b"]]}`,
		`{"note":"/etc/passwd"}`,
		`{"note":"dir/file.txt"}`,
		`{"note":"dir/file"}`,
		`{"note":"/etc/credentials"}`,
		`{"note":"dir/Credential-store"}`,
		`{"note":"readme.txt"}`,
		`{"note":"/"}`,
		`{"a":"/x/y.txt","b":"/x/y.txt","c":["/x/y.txt"]}`,
		`{"path":"/x/y.txt","other":"/x/y.txt"}`,
		`{"path":7,"file":true,"target":null,"note":1.5}`,
		`{"path":"/data/a.txt","n":3,"flag":false,"list":[1,"b/c.d",null]}`,
		`{"path":" /padded "}`,
	} {
		paths := nonNil(ExtractPathsFromToolArgs(json.RawMessage(args)))
		sort.Strings(paths)
		out.ExtractPaths = append(out.ExtractPaths, extractPathsVector{ArgsJSON: args, Paths: paths})
	}

	e, _ := newTestEngine("block")
	for _, c := range []struct {
		content, path, source string
		seq                   uint64
	}{
		{"alice,hunter2\nbob,s3cret-pass", "/data/users.xlsx", "files/read_file", 3},
		{"abcd", "/etc/secrets/a", "fs/read", 2},
		{"abcdefghij", "/etc/secrets/a", "fs/read", 4},
		{"abcdefghijk", "/etc/secrets/a", "fs/read", 5},
		{"  padded value here  \n", "/home/bob/.ssh/id_rsa", "fs/read", 6},
		{"-----BEGIN KEY-----\nMIIEvQIBADANBg\n-----END KEY-----", "/data/server.key", "fs/read", 7},
		{"naïve café ✓", "/data/server.pem", "fs/read", 8},
		{"value", "", "", 0},
		{"", "/data/server.pem", "fs/read", 9},
		{" \n\t ", "/data/server.pem", "fs/read", 10},
	} {
		// Register through the engine so forms come from the real attach path.
		state := &model.SessionState{SessionID: "path-taint"}
		e.addTainted(state, TaintPathDrivenContent(c.content, c.path, c.source, c.seq))
		tainted := []pathTaintedValue{}
		for _, tv := range state.Tainted {
			forms := []string{}
			for _, v := range tv.Variants {
				forms = append(forms, v.Form)
			}
			tainted = append(tainted, pathTaintedValue{
				ValueHex: hex.EncodeToString([]byte(tv.Value)),
				Hash:     tv.Hash,
				Preview:  tv.Preview,
				Forms:    forms,
				Source:   tv.Source,
				Seq:      tv.Seq,
			})
		}
		out.Taint = append(out.Taint, pathTaintVector{Content: c.content, Path: c.path, Source: c.source, Seq: c.seq, Tainted: tainted})
	}
	return out
}

func TestPathTaintVectors(t *testing.T) {
	checkVectorFile(t, "testdata/path_taint_vectors.json", "go test ./internal/engine -run PathTaintVectors -update", pathTaintVectors())
}
