// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

type chunkVector struct {
	Name     string        `json:"name"`
	InputHex string        `json:"input_hex"`
	N        int           `json:"n"`
	MinLen   int           `json:"min_len"`
	Chunks   []chunkOutput `json:"chunks"`
}

type chunkOutput struct {
	Form     string `json:"form"`
	ValueHex string `json:"value_hex"`
}

func TestChunkVectors(t *testing.T) {
	const path = "testdata/chunk_vectors.json"
	const token = "51TxJANEd0eR3aLt0k3n987654aBcDeF" +
		"ZQ8wSe6RtyUiOpLkJhGfDsAmNqVbCxY9"
	inputs := []struct {
		name, value string
		n, minLen   int
	}{
		{"pem", "prefix\n-----BEGIN PRIVATE KEY-----\r\n" + token + "\r\n-----END PRIVATE KEY-----\n", 0, 0},
		{"putty", "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n\nPrivate-Lines: 1\n" + token + "\nPrivate-MAC: 1234", 0, 0},
		{"putty_private_lines", "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\n" + token + "\nPrivate-MAC: 1234", 0, 0},
		{"long_token", "sk-live-" + token + token, 0, 0},
		{"low_entropy", strings.Repeat("A", 96), 0, 0},
		{"under_minimum", token[:63], 0, 0},
		{"at_minimum", token[:64], 0, 0},
		{"partial_tail", token + "abcdefg", 24, 32},
		{"mixed_entropy", strings.Repeat("A", 32) + token, 0, 0},
		{"below_floor", "aaaaaaabbbbbccccddddeeeefffgghhi", 32, 32},
		{"at_floor", strings.Repeat("abcdefgh", 4), 32, 32},
		{"above_floor", "aaaaaaabbbbbcccccdddddeeefffghij", 32, 32},
	}
	got := make([]chunkVector, 0, len(inputs))
	for _, input := range inputs {
		vector := chunkVector{
			Name: input.name, InputHex: hex.EncodeToString([]byte(input.value)),
			N: input.n, MinLen: input.minLen, Chunks: []chunkOutput{},
		}
		for _, chunk := range ContiguousChunks(input.value, input.n, input.minLen) {
			vector.Chunks = append(vector.Chunks, chunkOutput{chunk.Form, hex.EncodeToString([]byte(chunk.Value))})
		}
		got = append(got, vector)
	}
	if *updateEncodingVectors {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want []chunkVector
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d vectors, want %d", len(got), len(want))
	}
	for i, actual := range got {
		t.Run(actual.Name, func(t *testing.T) {
			expected := want[i]
			if actual.Name != expected.Name || actual.InputHex != expected.InputHex ||
				actual.N != expected.N || actual.MinLen != expected.MinLen {
				t.Fatalf("fixture input differs for %s", actual.Name)
			}
			if !slices.Equal(actual.Chunks, expected.Chunks) {
				t.Fatalf("chunks: got %v, want %v", actual.Chunks, expected.Chunks)
			}
		})
	}
}
