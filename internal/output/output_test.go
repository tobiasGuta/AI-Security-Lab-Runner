package output

import (
	"testing"
)

func TestBoundedWriter(t *testing.T) {
	bw := NewBoundedWriter(10)

	n, err := bw.Write([]byte("hello "))
	if err != nil || n != 6 {
		t.Fatalf("write failed: n=%d err=%v", n, err)
	}

	n, err = bw.Write([]byte("world from lab runner"))
	if err != nil || n != 21 {
		t.Fatalf("write failed: n=%d err=%v", n, err)
	}

	if !bw.Truncated {
		t.Errorf("expected Truncated to be true")
	}

	if bw.String() != "hello worl" {
		t.Errorf("expected 'hello worl', got '%s'", bw.String())
	}
}

func TestLimitString(t *testing.T) {
	s, trunc := LimitString("abcdef", 3)
	if !trunc || s != "abc" {
		t.Errorf("expected 'abc', true; got '%s', %v", s, trunc)
	}
}
