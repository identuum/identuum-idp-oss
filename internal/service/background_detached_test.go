package service

import (
	"context"
	"testing"
)

// The mail that password reset, verification resend and self-registration
// send after answering is waited for at shutdown, so a stop does not cut it
// off with the database pool closed underneath it.
func TestDetachedWork_WaitReturnsOnlyWhenTheWorkEnds(t *testing.T) {
	var d DetachedWork
	release := make(chan struct{})
	ended := make(chan struct{})
	d.Run(context.Background(), func(context.Context) { <-release; close(ended) })

	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if d.Wait(expired) {
		t.Fatal("Wait reported the work finished while it was still running")
	}

	waited := make(chan bool, 1)
	go func() { waited <- d.Wait(context.Background()) }()
	close(release)
	if !<-waited {
		t.Fatal("Wait did not report the finished work")
	}
	select {
	case <-ended:
	default:
		t.Fatal("Wait returned before the work ended")
	}
}

func TestDetachedWork_APanickingPieceStillCountsAsDone(t *testing.T) {
	var d DetachedWork
	d.Run(context.Background(), func(context.Context) { panic("boom") })
	if !d.Wait(context.Background()) {
		t.Fatal("a panicking piece of work kept Wait from returning")
	}
}
