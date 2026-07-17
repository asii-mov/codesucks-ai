package scan

import (
	"strings"
	"sync"
	"testing"
)

func TestRedactor_LongestFirst(t *testing.T) {
	r := NewRedactor()
	r.Add("secret")
	r.Add("supersecretvalue")
	got := r.Redact("a supersecretvalue and a plain secret here")
	if strings.Contains(got, "supersecretvalue") || strings.Contains(got, "secret") {
		t.Errorf("values not fully redacted: %s", got)
	}
}

func TestRedactor_IgnoresEmpty(t *testing.T) {
	r := NewRedactor()
	r.Add("")
	r.Add("   ")
	if got := r.Redact("nothing to redact"); got != "nothing to redact" {
		t.Errorf("unexpected change: %s", got)
	}
}

func TestRedactor_ConcurrentAddRedact(t *testing.T) {
	r := NewRedactor()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r.Add(strings.Repeat("x", n+1))
			_ = r.Redact("xxxxx")
		}(i)
	}
	wg.Wait()
}
