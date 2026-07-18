package respond

import (
	"testing"

	"deuswatch/internal/ingest"
)

func TestDefaultDecisionTableCoversAllEntities(t *testing.T) {
	want := []EntityType{EntityExternalIP, EntityHost, EntityUser, EntityHash}
	for _, e := range want {
		d, ok := DecisionFor(e)
		if !ok {
			t.Fatalf("decision-table missing entity %q", e)
		}
		if d.Action == "" {
			t.Fatalf("entity %q has no action", e)
		}
		if d.Enforced && d.Engine == "" {
			t.Fatalf("enforced entity %q has no owning engine", e)
		}
	}
}

func TestEntities(t *testing.T) {
	cases := []struct {
		name string
		ev   *ingest.Event
		want []EntityType
	}{
		{"nil", nil, nil},
		{"empty", &ingest.Event{}, nil},
		{
			"external ip only",
			&ingest.Event{Source: &ingest.Endpoint{IP: "203.0.113.7"}},
			[]EntityType{EntityExternalIP},
		},
		{
			"host only",
			&ingest.Event{Agent: &ingest.Agent{ID: "web01"}},
			[]EntityType{EntityHost},
		},
		{
			"all four, in table order",
			&ingest.Event{
				Source: &ingest.Endpoint{IP: "203.0.113.7"},
				Agent:  &ingest.Agent{ID: "web01"},
				User:   &ingest.User{Name: "deus"},
				File:   &ingest.File{HashSHA256: "abc"},
			},
			[]EntityType{EntityExternalIP, EntityHost, EntityUser, EntityHash},
		},
		{
			"blank fields do not count",
			&ingest.Event{
				Source: &ingest.Endpoint{IP: ""},
				Agent:  &ingest.Agent{ID: ""},
				User:   &ingest.User{Name: ""},
				File:   &ingest.File{HashSHA256: ""},
			},
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Entities(c.ev)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}
