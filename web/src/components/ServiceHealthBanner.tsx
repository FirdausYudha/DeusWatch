import { useEffect, useState } from 'react'
import { fetchServiceHealth, type ServiceHealth } from '../lib/api'
import { NoticeBanner } from './ui'

/**
 * ServiceHealthBanner warns, on every page, when a backend component has stopped reporting.
 *
 * It is global rather than a Dashboard widget on purpose. The worker is the only consumer of
 * `logs.normalized` and the only writer of events, so when it stops, nothing new is detected or
 * stored anywhere — and the operator hits that while reading Alerts, or Agents, or Response, not
 * necessarily while looking at the Dashboard. On 2026-09-04 it was absent for eleven hours and
 * every screen looked normal, because the alarm for that condition (AGENT_DISCONNECT_AFTER) runs
 * inside the worker itself.
 *
 * Silent while everything is healthy, and silent on a lookup failure: if the API cannot answer,
 * the honest conclusion is "we don't know", and telling an operator to restart a healthy worker
 * because the network hiccuped would be worse than saying nothing.
 */
export default function ServiceHealthBanner() {
  const [services, setServices] = useState<ServiceHealth[] | null>(null)

  useEffect(() => {
    const load = () => {
      fetchServiceHealth()
        .then(setServices)
        .catch(() => setServices(null))
    }
    load()
    // 30s: the worker beats every 30s and the API calls it stale after 100s, so this surfaces a
    // dead worker within about two minutes and clears the banner within 30s of it coming back.
    const t = setInterval(load, 30_000)
    return () => clearInterval(t)
  }, [])

  const down = (services ?? []).filter((s) => !s.alive)
  if (down.length === 0) return null

  return (
    <div className="px-5 pt-4">
      {down.map((s) => (
        <NoticeBanner
          key={s.service}
          tone="danger"
          title={
            s.ever_seen
              ? `The ${s.service} has stopped reporting — detection is not running`
              : `The ${s.service} has never reported — detection has not started`
          }
        >
          {s.ever_seen ? (
            <>
              Last heartbeat {relative(s.age_seconds)}
              {s.version ? ` (build ${s.version})` : ''}. Nothing is being detected or stored while
              it is down: no alerts, no brute-force, no FIM, and no notifications. Agents keep
              shipping logs, so nothing is lost — the queue drains once it comes back.{' '}
              <code className="font-mono text-[11.5px]">
                docker compose -f deploy/docker-compose.yml up -d worker
              </code>
            </>
          ) : (
            <>
              No heartbeat has ever been recorded, so the worker container is most likely not
              running at all. Check that it exists — a stopped container will not appear in
              <code className="mx-1 font-mono text-[11.5px]">docker compose ps</code> without
              <code className="mx-1 font-mono text-[11.5px]">-a</code>. If this deployment was just
              upgraded, give it a minute: the banner clears on the worker's first heartbeat.
            </>
          )}
        </NoticeBanner>
      ))}
    </div>
  )
}

// relative renders an age the way an operator reads it, rather than as raw seconds.
function relative(seconds: number): string {
  if (seconds < 90) return `${Math.round(seconds)}s ago`
  const mins = Math.round(seconds / 60)
  if (mins < 90) return `${mins} min ago`
  const hours = Math.round(seconds / 3600)
  if (hours < 48) return `${hours} h ago`
  return `${Math.round(seconds / 86400)} days ago`
}
