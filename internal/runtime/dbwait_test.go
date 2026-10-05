package runtime

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// FUNC-M9: when the database comes back the wait ends, the NOT-SERVING
// surface steps aside (the listen address is free for the real server), and
// the boot goes on.
func TestWaitForDatabase_EndsWhenTheDatabaseAnswers(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	var calls atomic.Int32
	up := make(chan struct{})
	ping := func(context.Context) error {
		calls.Add(1)
		select {
		case <-up:
			return nil
		default:
			return errors.New("down")
		}
	}
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- WaitForDatabase(context.Background(), "", DatabaseWaitOptions{Listen: addr, Ping: ping, Stderr: &stderr, MaxInterval: time.Second})
	}()
	var res *http.Response
	for i := 0; i < 50; i++ {
		if res, err = http.Get("http://" + addr + "/health"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/health while waiting: %v %v; want 503", res, err)
	}
	_ = res.Body.Close()
	close(up)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wait = %v; want nil once the database answers", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait did not end when the database answered")
	}
	l2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the listen address is still held after the wait: %v", err)
	}
	_ = l2.Close()
}

func TestWaitForDatabase_AnAnsweringDatabaseServesNothing(t *testing.T) {
	var stderr bytes.Buffer
	if err := WaitForDatabase(context.Background(), "", DatabaseWaitOptions{Listen: "127.0.0.1:0", Ping: func(context.Context) error { return nil }, Stderr: &stderr}); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Errorf("a database that answers printed %q", stderr.String())
	}
}
