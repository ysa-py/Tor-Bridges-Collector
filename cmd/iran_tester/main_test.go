package main

import (
	"fmt"
	"testing"
)

func TestValidateWorkersAcceptsPositiveCounts(t *testing.T) {
	for _, workers := range []int{1, 100} {
		t.Run(fmt.Sprintf("workers_%d", workers), func(t *testing.T) {
			if err := validateWorkers(workers); err != nil {
				t.Fatalf("validateWorkers(%d) returned error: %v", workers, err)
			}
		})
	}
}

func TestValidateWorkersRejectsNonPositiveCounts(t *testing.T) {
	for _, workers := range []int{0, -1} {
		t.Run(fmt.Sprintf("workers_%d", workers), func(t *testing.T) {
			err := validateWorkers(workers)
			if err == nil {
				t.Fatalf("validateWorkers(%d) returned nil error, want validation failure", workers)
			}
			want := fmt.Sprintf("workers must be >= 1, got %d", workers)
			if err.Error() != want {
				t.Fatalf("validateWorkers(%d) error=%q, want %q", workers, err.Error(), want)
			}
		})
	}
}
