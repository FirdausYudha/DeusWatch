package main

import (
	"context"
	"fmt"
	"time"

	"deuswatch/internal/assistant"
	"deuswatch/internal/enrich"
	"deuswatch/internal/hashrep"
	"deuswatch/internal/integrations"
	"deuswatch/internal/llm"
	"deuswatch/internal/secret"
	"deuswatch/internal/store"
)

// Live reputation lookups for the assistant.
//
// The cache is always consulted first. Most addresses an operator asks about were enriched by the
// pipeline hours ago, and spending an AbuseIPDB request to learn what is already in the table is
// how a free tier is gone by lunchtime. A live call happens only when there is nothing cached, or
// what is cached has expired, and the result is written back so the next question is free.

const (
	// liveLookupBudget bounds one lookup. The operator is waiting, and a provider having a bad day
	// must not become the assistant having a bad day.
	liveLookupBudget = 8 * time.Second
	// cacheTTL for results this path fetches. Matches the enrichment pipeline's own window closely
	// enough that the two do not fight over the same row.
	cacheTTL = 12 * time.Hour
)

// ctiProvider builds an IP reputation provider from the Integrations registry, or false when the
// operator has configured none.
func ctiProvider(ctx context.Context, st *store.Store) (enrich.Provider, bool) {
	cipher, _, err := secret.FromEnv()
	if err != nil {
		return nil, false
	}
	is := integrations.NewStore(st.Pool(), cipher)
	var abuseKey, otxKey string
	if rows, rerr := is.Resolve(ctx, "abuseipdb"); rerr == nil && len(rows) > 0 {
		abuseKey = rows[0].Config["api_key"]
	}
	if rows, rerr := is.Resolve(ctx, "otx"); rerr == nil && len(rows) > 0 {
		otxKey = rows[0].Config["api_key"]
	}
	if abuseKey == "" && otxKey == "" {
		return nil, false
	}
	// Geo off: the address lookup already reports the country the events carry, and a third call
	// to a free geo service for a field we have is latency the operator pays for nothing.
	return enrich.BuildProvider(abuseKey, otxKey, false, "", "", nil)
}

// hashProvider builds a file-hash reputation provider the same way.
func hashProvider(ctx context.Context, st *store.Store) (hashrep.Provider, bool) {
	cipher, _, err := secret.FromEnv()
	if err != nil {
		return nil, false
	}
	is := integrations.NewStore(st.Pool(), cipher)
	var vtKey, mbKey string
	circl := false
	if rows, rerr := is.Resolve(ctx, "virustotal"); rerr == nil && len(rows) > 0 {
		vtKey = rows[0].Config["api_key"]
	}
	if rows, rerr := is.Resolve(ctx, "malwarebazaar"); rerr == nil && len(rows) > 0 {
		mbKey = rows[0].Config["api_key"]
	}
	if rows, rerr := is.Resolve(ctx, "circl_hashlookup"); rerr == nil && len(rows) > 0 {
		circl = true
	}
	return hashrep.BuildProvider(vtKey, mbKey, circl)
}

// turnTexts flattens a conversation to the message bodies, which is all the address scan needs.
func turnTexts(h []llm.ChatTurn) []string {
	out := make([]string, len(h))
	for i, t := range h {
		out[i] = t.Content
	}
	return out
}

// addressReport builds one address block. live=false stops short of any network call, which is what
// a carried-forward address gets: it may have come from the model's own turn and so may not exist.
func addressReport(ctx context.Context, st *store.Store, ip string, mlActive, live bool) string {
	d, err := st.IPDossierFor(ctx, ip)
	if err != nil {
		return ""
	}
	act := st.IPActivityFor(ctx, ip)
	dos := assistant.Dossier{
		IP: d.IP, Found: d.Found, Blocked: d.Blocked, Listed: d.Whitelisted,
		Offenses: d.Offenses, Total: d.Total, Pending: d.Pending,
		LastStatus: d.LastStatus, LastReason: d.LastReason, LastAgent: d.LastAgent,
		Events24h:    d.Events24h,
		BlockedUntil: fmtTimePtr(d.BlockedUntil), LastSeen: fmtTimePtr(d.LastSeen),
		HasScore: d.HasScore, Score: d.Score, Anomaly: d.Anomaly, Band: d.Band,
		MLActive: mlActive,
		Events:   act.Events, Rules: act.Rules, Agents: act.Agents, Countries: act.Countries,
		FirstSeen: fmtTimePtr(act.FirstSeen), LastSeenEvent: fmtTimePtr(act.LastSeen),
	}
	// Reputation last, because it is the only part that may reach the network. Cache first,
	// live only when nothing usable is stored; see below.
	reputationFor(ctx, st, ip, &dos, live)
	return assistant.IPReport(dos)
}

// reputationFor fills the reputation half of an address report: cache first, live only if needed
// and only when the caller allows it.
func reputationFor(ctx context.Context, st *store.Store, ip string, d *assistant.Dossier, live bool) {
	c := st.CTIFor(ctx, ip)
	if c.Found && c.Fresh {
		d.HasCTI, d.Abuse, d.OTX = true, c.AbuseConfidence, c.OTXPulses
		d.CTICountry, d.CTISource, d.CTIAge = c.Country, c.Feed, humanAge(c.CheckedAt)
		return
	}
	if !live {
		if c.Found { // stale but free, and better than nothing
			d.HasCTI, d.Abuse, d.OTX = true, c.AbuseConfidence, c.OTXPulses
			d.CTICountry, d.CTISource, d.CTIAge = c.Country, c.Feed, humanAge(c.CheckedAt)
		}
		return
	}

	p, ok := ctiProvider(ctx, st)
	if !ok {
		// Nothing configured. A stale row is still better than silence, clearly labelled as stale.
		if c.Found {
			d.HasCTI, d.Abuse, d.OTX = true, c.AbuseConfidence, c.OTXPulses
			d.CTICountry, d.CTISource, d.CTIAge = c.Country, c.Feed, humanAge(c.CheckedAt)
		}
		return
	}

	lctx, cancel := context.WithTimeout(ctx, liveLookupBudget)
	defer cancel()
	ind, lerr := p.Lookup(lctx, ip)
	if lerr != nil {
		if c.Found { // the live call failed; the stale row is what we have
			d.HasCTI, d.Abuse, d.OTX = true, c.AbuseConfidence, c.OTXPulses
			d.CTICountry, d.CTISource, d.CTIAge = c.Country, c.Feed, humanAge(c.CheckedAt)
		}
		return
	}
	d.HasCTI, d.CTILive = true, true
	d.Abuse, d.OTX = ind.AbuseConfidence, ind.OTXPulseCount
	d.CTICountry, d.CTISource = ind.CountryISO, ind.FeedName
	st.SaveCTI(ctx, ip, ind.AbuseConfidence, ind.OTXPulseCount, ind.CountryISO, ind.FeedName, cacheTTL)
}

// hashReportFor builds one file-hash report, consulting the cache before any provider.
func hashReportFor(ctx context.Context, st *store.Store, sha string) assistant.FileReport {
	f := assistant.FileReport{SHA256: sha, Paths: st.FileHashSightings(ctx, sha)}

	cached := st.HashRepFor(ctx, sha)
	if cached.Found && cached.Fresh {
		f.HasRep, f.ProvidersEnabled = true, true
		f.Verdict, f.Source, f.Detail = cached.Verdict, cached.Source, cached.Detail
		f.Age = humanAge(cached.CheckedAt)
		return f
	}

	p, ok := hashProvider(ctx, st)
	f.ProvidersEnabled = ok
	if !ok {
		if cached.Found {
			f.HasRep, f.ProvidersEnabled = true, true
			f.Verdict, f.Source, f.Detail = cached.Verdict, cached.Source, cached.Detail
			f.Age = humanAge(cached.CheckedAt)
		}
		return f
	}

	lctx, cancel := context.WithTimeout(ctx, liveLookupBudget)
	defer cancel()
	ind, lerr := p.LookupHash(lctx, sha)
	if lerr != nil {
		if cached.Found {
			f.HasRep = true
			f.Verdict, f.Source, f.Detail = cached.Verdict, cached.Source, cached.Detail
			f.Age = humanAge(cached.CheckedAt)
		}
		return f
	}
	f.HasRep, f.Live = true, true
	f.Verdict, f.Source, f.Detail = string(ind.Verdict), ind.Source, ind.Detail
	st.SaveHashRep(ctx, sha, string(ind.Verdict), ind.Source, ind.Detail, cacheTTL)
	return f
}

// humanAge phrases how old a cached figure is. Shown rather than hidden, because a confidence of 0
// from a month ago and one from this morning are different claims, and reporting them identically
// is how an address that has since turned bad stays clean in the telling.
func humanAge(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s) ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s) ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d day(s) ago", int(d.Hours()/24))
	}
}
