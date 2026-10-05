import { useEffect, useState } from 'react'

// The Topbar clock: local time, date, zone, and UTC alongside it.
//
// UTC is not decoration. Every timestamp DeusWatch stores is UTC, and several views render it as
// such, so an operator reading an alert at 02:14 has to know whether that is their 02:14 or the
// database's. A clock that shows only local time quietly invites that mistake, and the mistake
// looks like an attack happening seven hours from when it did.
//
// The zone label is what "location" means on a security console. A city would be decoration; the
// offset is what you need to correlate a log line with a phone call.

/** The short zone name the platform uses, e.g. WIB, GMT+7, CEST. */
function zoneLabel(d: Date): string {
  try {
    const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' }).formatToParts(d)
    const name = parts.find((p) => p.type === 'timeZoneName')?.value
    if (name) return name
  } catch {
    // Intl can throw on an exotic locale; the offset below always works.
  }
  const off = -d.getTimezoneOffset() / 60
  return `UTC${off >= 0 ? '+' : ''}${off}`
}

/** The IANA zone, e.g. Asia/Jakarta. Shown on hover: it is precise but too long for the bar. */
function zoneName(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || ''
  } catch {
    return ''
  }
}

export default function Clock() {
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    // Aligned to the next whole second rather than ticking every 1000ms from mount, so the display
    // does not sit visibly behind the system clock.
    let id: number
    const tick = () => {
      setNow(new Date())
      id = window.setTimeout(tick, 1000 - (Date.now() % 1000))
    }
    id = window.setTimeout(tick, 1000 - (Date.now() % 1000))
    return () => window.clearTimeout(id)
  }, [])

  const time = now.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
  const date = now.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short' })
  const utc = now.toISOString().slice(11, 16)
  const zone = zoneLabel(now)
  const iana = zoneName()

  return (
    <div
      className="hidden flex-col items-end leading-tight md:flex"
      title={`${now.toLocaleString()}${iana ? ` (${iana})` : ''} · ${now.toISOString().slice(0, 19).replace('T', ' ')} UTC`}
    >
      {/* tabular-nums stops the whole bar twitching every second as digit widths change. */}
      <span className="text-[13px] font-semibold tabular-nums text-fg">
        {time} <span className="font-normal text-dim">{zone}</span>
      </span>
      <span className="text-[11.5px] tabular-nums text-dim">
        {date} · {utc} UTC
      </span>
    </div>
  )
}
