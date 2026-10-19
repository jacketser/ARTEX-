package honeydetect

import "testing"

func TestMetadataSignals(t *testing.T) {
	for _, tc := range []struct {
		name       string
		in         Input
		confidence string
		score      int
	}{
		{"none", Input{}, "none", 0},
		{"ordinary admin", Input{Title: "Admin Login", Service: "SSH"}, "none", 0},
		{"substring", Input{Title: "cowrieshell hfishery myhoneypotapp"}, "none", 0},
		{"single", Input{Title: "Cowrie"}, "low", 35},
		{"case", Input{Banner: "SSH-2.0-COWRIE"}, "low", 35},
		{"copied fields", Input{Title: "Cowrie", Banner: "Cowrie", ServerHeader: "Cowrie"}, "low", 35},
		{"same surface", Input{Title: "Cowrie console", Technologies: []string{"Cowrie", "Cowrie"}}, "low", 35},
		{"two surfaces", Input{Title: "HFish Console", ServerHeader: "HFish/1"}, "medium", 65},
		{"three surfaces", Input{Title: "HFish Console", ServerHeader: "HFish/1", Banner: "HFish service"}, "high", 85},
		{"many names single field", Input{Title: "Cowrie Dionaea HFish honeypot 蜜罐"}, "low", 35},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Detect(tc.in)
			if r.Confidence != tc.confidence || r.Score != tc.score || r.Matched != (tc.score > 0) {
				t.Fatalf("%+v", r)
			}
			if r.Signals == nil || r.Evidence == nil || r.Limitations == "" {
				t.Fatal("incomplete result")
			}
		})
	}
	a := Input{Technologies: []string{"Cowrie", "ssh"}}
	b := Input{Technologies: []string{"ssh", "Cowrie"}}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("ordering changed fingerprint")
	}
	if a.Technologies[0] != "Cowrie" {
		t.Fatal("input mutated")
	}
}
