package whois

import (
	"errors"
	"testing"
)

func TestResult_Deepest(t *testing.T) {
	tests := []struct {
		name string
		hops []Hop
		want string // Server of the expected hop, "" for nil
	}{
		{
			name: "no hops",
			hops: nil,
			want: "",
		},
		{
			name: "single successful hop",
			hops: []Hop{{Server: "whois.iana.org"}},
			want: "whois.iana.org",
		},
		{
			name: "walks past a failed trailing hop to the last success",
			hops: []Hop{
				{Server: "whois.iana.org"},
				{Server: "whois.verisign-grs.com"},
				{Server: "whois.example-registrar.com", Err: errors.New("dial timeout")},
			},
			want: "whois.verisign-grs.com",
		},
		{
			name: "every hop failed",
			hops: []Hop{
				{Server: "whois.iana.org", Err: errors.New("dial refused")},
				{Server: "whois.verisign-grs.com", Err: errors.New("dial timeout")},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{Domain: "example.com", Hops: tt.hops}
			got := r.Deepest()
			switch {
			case tt.want == "" && got != nil:
				t.Errorf("Deepest() = %+v, want nil", got)
			case tt.want != "" && got == nil:
				t.Errorf("Deepest() = nil, want hop with Server %q", tt.want)
			case tt.want != "" && got.Server != tt.want:
				t.Errorf("Deepest().Server = %q, want %q", got.Server, tt.want)
			}
		})
	}
}
