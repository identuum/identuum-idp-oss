package runtime_test

import (
	"context"
	"database/sql"
	"io"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/pkg/migrations"
	"github.com/identuum/identuum-idp-oss/pkg/runtime"

	shim "github.com/identuum/identuum-idp-oss/internal/pkg/runtime"
)

// OSS-SEAM-1 proof 1: a caller outside the package composes the runtime with
// public types only — Options, Runtime, Lifecycle, migrations.Apply/Current.
// Compiling this function is the proof; it is never called with a database.
func composeLikeACaller(ctx context.Context, db *sql.DB, dsn string) error {
	if _, err := migrations.Apply(ctx, db); err != nil {
		return err
	}
	_ = migrations.Current()
	rt, err := runtime.New(runtime.Options{Addr: "127.0.0.1:0", Issuer: "https://idp.example.test", DatabaseURL: dsn})
	if err != nil {
		return err
	}
	var lc runtime.Lifecycle = rt
	if err := lc.Start(ctx); err != nil {
		return err
	}
	select {
	case <-lc.Done():
		return lc.ServeErr()
	case <-ctx.Done():
	}
	return lc.Shutdown(context.Background())
}

var _ = composeLikeACaller

// The public Runtime promotes no engine, pool or other private accessor: its
// method set is exactly the lifecycle and the two addresses.
func TestRuntime_MethodSetIsTheLifecycleOnly(t *testing.T) {
	var got []string
	rt := reflect.TypeOf(&runtime.Runtime{})
	for i := 0; i < rt.NumMethod(); i++ {
		got = append(got, rt.Method(i).Name)
	}
	sort.Strings(got)
	want := []string{"Addr", "Done", "Health", "MetricsAddr", "ServeErr", "Serving", "Shutdown", "Start"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("*runtime.Runtime methods = %v; want %v", got, want)
	}
	if reflect.TypeOf(runtime.Runtime{}).NumField() != 1 || reflect.TypeOf(runtime.Runtime{}).Field(0).IsExported() {
		t.Fatal("runtime.Runtime must hold only its private backing")
	}
}

// OSS-SEAM-1 proof 3: the facade delegates to the existing lifecycle — each
// answer equals the internal path's answer for the same input, errors
// included (the internal path is the shim the binary uses).
func TestRuntime_DelegatesTheLifecycle(t *testing.T) {
	t.Run("an empty Addr is refused as the internal path refuses it", func(t *testing.T) {
		_, perr := runtime.New(runtime.Options{})
		_, ierr := shim.New(shim.Config{})
		if perr == nil || ierr == nil || perr.Error() != ierr.Error() {
			t.Fatalf("public %v, internal %v: want the same refusal", perr, ierr)
		}
	})
	t.Run("Start with no database fails as the internal path fails", func(t *testing.T) {
		quiet := func(string) string { return "" }
		p, err := runtime.New(runtime.Options{Addr: "127.0.0.1:0", Stdout: io.Discard, Stderr: io.Discard, Getenv: quiet})
		if err != nil {
			t.Fatal(err)
		}
		i, err := shim.New(shim.Config{Addr: "127.0.0.1:0", Stdout: io.Discard, Stderr: io.Discard, Getenv: quiet})
		if err != nil {
			t.Fatal(err)
		}
		perr, ierr := p.Start(context.Background()), i.Start(context.Background())
		if perr == nil || ierr == nil || perr.Error() != ierr.Error() {
			t.Fatalf("public %v, internal %v: want the same Start error", perr, ierr)
		}
		if p.Addr() != i.Addr() || p.Serving() != i.Serving() || (p.ServeErr() == nil) != (i.ServeErr() == nil) {
			t.Fatalf("after a failed Start: public Addr %q Serving %v, internal Addr %q Serving %v",
				p.Addr(), p.Serving(), i.Addr(), i.Serving())
		}
	})
	t.Run("Shutdown before Start is nil, twice", func(t *testing.T) {
		p, err := runtime.New(runtime.Options{Addr: "127.0.0.1:0"})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := p.Shutdown(ctx); err != nil {
			t.Fatalf("first Shutdown: %v", err)
		}
		if err := p.Shutdown(ctx); err != nil {
			t.Fatalf("second Shutdown: %v", err)
		}
	})
	t.Run("a Runtime not built by New refuses Start and Shutdown", func(t *testing.T) {
		var zero runtime.Runtime
		if zero.Start(context.Background()) == nil || zero.Shutdown(context.Background()) == nil {
			t.Fatal("the zero Runtime must refuse, not panic or succeed")
		}
	})
}
