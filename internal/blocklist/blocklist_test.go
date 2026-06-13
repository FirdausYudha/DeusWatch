package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseLines(t *testing.T) {
	data := []byte("# header comment\n; semicolon comment\n\n45.155.205.99\n185.220.0.0/16 # tor exit\n1.2.3.4,malware\n")
	got := ParseLines(data)
	want := []string{"45.155.205.99", "185.220.0.0/16", "1.2.3.4"}
	if len(got) != len(want) {
		t.Fatalf("jumlah token %d, mau %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("token[%d]=%q, mau %q", i, got[i], want[i])
		}
	}
}

func TestSetContains(t *testing.T) {
	s := NewSet()
	s.Replace([]string{"45.155.205.99", "185.220.0.0/16", "bogus", "10.0.0.0/8"})
	if s.Len() != 3 { // bogus dilewati
		t.Fatalf("Len=%d, mau 3", s.Len())
	}
	cases := map[string]bool{
		"45.155.205.99": true,  // IP eksak
		"185.220.5.7":   true,  // dalam CIDR
		"10.255.1.1":    true,  // dalam /8
		"8.8.8.8":       false, // bukan anggota
		"185.221.0.1":   false, // di luar CIDR
	}
	for ip, want := range cases {
		if got := s.Contains(ip); got != want {
			t.Errorf("Contains(%q)=%v, mau %v", ip, got, want)
		}
	}
}

func TestReplaceSwaps(t *testing.T) {
	s := NewSet()
	s.Replace([]string{"1.1.1.1"})
	if !s.Contains("1.1.1.1") {
		t.Fatal("entri awal hilang")
	}
	s.Replace([]string{"2.2.2.2"})
	if s.Contains("1.1.1.1") || !s.Contains("2.2.2.2") {
		t.Fatal("Replace harus mengganti, bukan menambah")
	}
}

func TestLoadHTTP(t *testing.T) {
	feed1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("# feed1\n45.155.205.99\n185.220.0.0/16\n"))
	}))
	defer feed1.Close()
	feed2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("203.0.113.10\n"))
	}))
	defer feed2.Close()

	set, err := Load(context.Background(), feed1.Client(), []string{feed1.URL, feed2.URL})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, ip := range []string{"45.155.205.99", "185.220.1.1", "203.0.113.10"} {
		if !set.Contains(ip) {
			t.Errorf("%s harus ada di blocklist gabungan", ip)
		}
	}
}

func TestLoadPartialFailureStillLoads(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("9.9.9.9\n"))
	}))
	defer good.Close()

	// satu URL valid + satu yang tak terjangkau -> tetap memuat yang valid.
	set, err := Load(context.Background(), good.Client(), []string{good.URL, "http://127.0.0.1:0/x"})
	if err != nil {
		t.Fatalf("kegagalan parsial tak boleh menggagalkan Load: %v", err)
	}
	if !set.Contains("9.9.9.9") {
		t.Fatal("entri valid harus tetap dimuat")
	}
}

func TestLoadAllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := Load(context.Background(), srv.Client(), []string{srv.URL}); err == nil {
		t.Fatal("semua sumber gagal harus mengembalikan error")
	}
}
