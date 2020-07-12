package resolver

import (
	"testing"
)

func TestResolveInternal(t *testing.T) {
	tests := map[string]int{
		"docs.hackerone.com": 4,
	}

	client, err := New([]string{"1.1.1.1:53", "8.8.8.8:53"}, 5)
	if err != nil {
		t.Fatalf("Could not create client: %s\n", err)
	}

	for test, count := range tests {
		results, err := client.Resolve(test)
		if err != nil {
			t.Fatalf("Could not resolve host %s: %s\n", test, err)
		}

		if len(results.IPs) != count {
			t.Fatalf("Expected %d results got %v\n", count, results)
		}
	}
}
