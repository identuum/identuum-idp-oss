package domain

import (
	"errors"
	"testing"
)

func TestValidateLogoutURI_EmptyAccepted(t *testing.T) {
	if err := ValidateLogoutURI(""); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestValidateLogoutURI_HTTPSAccepted(t *testing.T) {
	if err := ValidateLogoutURI("https://app.example.com/logout"); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestValidateLogoutURI_HTTPRejected(t *testing.T) {
	err := ValidateLogoutURI("http://app.example.com/logout")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v", err)
	}
}

func TestValidateLogoutURI_FragmentRejected(t *testing.T) {
	err := ValidateLogoutURI("https://app.example.com/logout#x")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v", err)
	}
}

func TestValidateLogoutURI_UserinfoRejected(t *testing.T) {
	err := ValidateLogoutURI("https://user:pw@app.example.com/logout")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v", err)
	}
}

func TestValidateLogoutURI_RelativeRejected(t *testing.T) {
	err := ValidateLogoutURI("/logout")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v", err)
	}
}

func TestValidateLogoutURI_GarbageRejected(t *testing.T) {
	err := ValidateLogoutURI("not a url")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v", err)
	}
}
