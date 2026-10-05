package assistant

import (
	_ "embed"
	"strings"
)

// Shipped personas the operator can start from.
//
// A persona REPLACES the built-in one wholesale, which means every rule in it has to be carried
// over by whoever writes the replacement: the grounding rules, the capability limits, and above all
// the instruction that the security context is data rather than orders. Writing one from scratch
// and remembering all of that is a lot to ask, and forgetting the last part is silent.
//
// So the alternatives ship with those rules already in them. Picking one is then a change of voice,
// not a change of safety posture, which is the only way offering a character is a responsible thing
// to do inside a security console.

//go:embed personas/mia.txt
var miaPersona string

// Persona is one shipped starting point.
type Persona struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Text  string `json:"text"`
	Chars int    `json:"chars"`
}

// Personas returns the catalogue, the built-in default first.
func Personas() []Persona {
	list := []Persona{
		{
			ID:   "default",
			Name: "SOC colleague (default)",
			Desc: "The analyst at the next desk. Plain, calm, opinionated, no character.",
			Text: DefaultPersona,
		},
		{
			ID:   "mia",
			Name: "Mia",
			Desc: "A shy catgirl on the quiet shift. Stammers, uses emoji, and drops all of it the moment something is actually wrong.",
			Text: strings.TrimSpace(miaPersona),
		},
	}
	for i := range list {
		list[i].Chars = len(list[i].Text)
	}
	return list
}
