package main

import (
	"os"
	"strings"
	"testing"
)

func TestDoctorDoesNotExposeInvalidDSN(t *testing.T) {
	var output strings.Builder
	checkDatabase("postgres://user:VERY_PRIVATE_PASSWORD@invalid.invalid/db?connect_timeout=1", func(a, b, c string) { output.WriteString(a + b + c) })
	if strings.Contains(output.String(), "VERY_PRIVATE_PASSWORD") || !strings.Contains(output.String(), "FAIL") {
		t.Fatalf("unexpected diagnostic: %s", output.String())
	}
}

func TestDoctorWritableCleansProbe(t *testing.T) {
	dir := t.TempDir()
	if err := checkWritable(dir); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatalf("probe left files: %v %v", files, err)
	}
	if err := checkWritable(dir + "/missing"); err == nil {
		t.Fatal("missing directory passed")
	}
}
