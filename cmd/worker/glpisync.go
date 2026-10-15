package main

import (
	"context"
	"log"
	"strconv"
	"time"

	"deuswatch/internal/glpi"
	"deuswatch/internal/integrations"
	"deuswatch/internal/tickets"
)

// GLPI mirror (gap 4 of the hospital field insight, the part the ticketing work left open).
//
// The team works in GLPI. A security tool with its own ticket queue asks them to work in two
// places, and the field discussion said plainly which place loses. So DeusWatch pushes its tickets
// into GLPI and reads their status back.
//
// One-way for content, read-only for status: DeusWatch owns what a ticket says, GLPI owns how far
// along it is. Nothing here writes a field GLPI considers its own, which is what makes conflict
// resolution unnecessary rather than merely postponed.

const (
	glpiSyncInterval = 60 * time.Second
	// Per-cycle caps. A backlog drains over several cycles instead of opening one long session
	// that holds a GLPI connection for minutes.
	glpiPushBatch = 50
	glpiPullBatch = 100
)

func runGLPISync(ctx context.Context, st *tickets.Store, intStore *integrations.Store) {
	if intStore == nil {
		return // no secrets cipher: the connector's tokens cannot be read, so there is nothing to do
	}
	t := time.NewTicker(glpiSyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			glpiSyncOnce(ctx, st, intStore)
		}
	}
}

func glpiSyncOnce(ctx context.Context, st *tickets.Store, intStore *integrations.Store) {
	cfgs, err := intStore.Resolve(ctx, "glpi")
	if err != nil {
		log.Printf("worker: resolve GLPI integration: %v", err)
		return
	}
	if len(cfgs) == 0 {
		return // not configured, or disabled
	}
	// One GLPI per installation. Configuring two would make "which one owns the status" ambiguous,
	// so the first enabled connector wins and the rest are called out rather than silently ignored.
	if len(cfgs) > 1 {
		log.Printf("worker: %d GLPI integrations are enabled; using %q and ignoring the rest",
			len(cfgs), cfgs[0].Name)
	}
	c := cfgs[0].Config

	insecure, _ := strconv.ParseBool(c["insecure_tls"])
	client := glpi.New(c["url"], c["app_token"], c["user_token"], insecure)

	sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	sess, err := client.Open(sctx)
	if err != nil {
		log.Printf("worker: GLPI session: %v", err)
		return
	}
	// Sessions are a finite resource on the GLPI side; leaking one per minute exhausts the
	// instance's session table and takes GLPI down by accident.
	defer func() {
		if cerr := sess.Close(context.WithoutCancel(sctx)); cerr != nil {
			log.Printf("worker: GLPI killSession: %v", cerr)
		}
	}()

	category, _ := strconv.Atoi(c["category_id"])
	requester, _ := strconv.Atoi(c["requester_id"])
	glpiPush(sctx, st, sess, category, requester)
	glpiPull(sctx, st, sess)
}

// glpiPush creates a GLPI ticket for each DeusWatch ticket that does not have one.
func glpiPush(ctx context.Context, st *tickets.Store, sess *glpi.Session, category, requester int) {
	pending, err := st.UnpushedTickets(ctx, glpiPushBatch)
	if err != nil {
		log.Printf("worker: load tickets to push: %v", err)
		return
	}
	for i := range pending {
		t := &pending[i]
		id, err := sess.CreateTicket(ctx, glpi.NewTicket{
			Title:     t.Title,
			Content:   tickets.GLPIContent(t),
			Urgency:   glpi.UrgencyFromSeverity(t.Severity),
			Category:  category,
			Requester: requester,
		})
		if err != nil {
			// Stop the batch rather than hammering a GLPI that is down or rejecting the token:
			// the remaining tickets are still unpushed and the next cycle picks them up.
			log.Printf("worker: push ticket %s to GLPI: %v", t.ID, err)
			return
		}
		if err := st.MarkPushed(ctx, t.ID, id); err != nil {
			// The GLPI ticket exists but the link was not recorded, so the next cycle will push it
			// again and create a duplicate. Logged loudly because that is the one way this sync
			// produces mess a human has to clean up.
			log.Printf("worker: GLPI ticket %d created but the link to %s was NOT saved "+
				"(a duplicate will be pushed next cycle): %v", id, t.ID, err)
			return
		}
		log.Printf("worker: ticket %s pushed to GLPI as #%d", t.ID, id)
	}
}

// glpiPull reads GLPI's status back for the tickets already linked.
func glpiPull(ctx context.Context, st *tickets.Store, sess *glpi.Session) {
	linked, err := st.LinkedLiveTickets(ctx, glpiPullBatch)
	if err != nil {
		log.Printf("worker: load linked tickets: %v", err)
		return
	}
	for i := range linked {
		t := &linked[i]
		if t.GLPIID == nil {
			continue
		}
		raw, err := sess.TicketStatus(ctx, *t.GLPIID)
		if err != nil {
			log.Printf("worker: read GLPI ticket %d: %v", *t.GLPIID, err)
			return // same reasoning as the push: do not hammer a GLPI that is unwell
		}
		status, ok := glpi.StatusToDeusWatch(raw)
		if !ok {
			// A status this version of GLPI has and we do not. Leaving the ticket alone is the
			// only safe move: guessing could resolve something that is not resolved.
			log.Printf("worker: GLPI ticket %d has unmapped status %d, leaving %s unchanged",
				*t.GLPIID, raw, t.ID)
			continue
		}
		if status == t.Status {
			if err := st.TouchGLPISync(ctx, t.ID); err != nil {
				log.Printf("worker: touch sync on %s: %v", t.ID, err)
			}
			continue
		}
		if _, err := st.ApplyGLPIStatus(ctx, t.ID, status); err != nil {
			log.Printf("worker: apply GLPI status to %s: %v", t.ID, err)
			continue
		}
		log.Printf("worker: ticket %s → %s (from GLPI #%d)", t.ID, status, *t.GLPIID)
	}
}
