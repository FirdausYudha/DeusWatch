// DocLink renders a "See documentation" link to the feature's page in the GitHub docs, so each
// feature in the UI points at how to set it up. `file` is a path under docs/ (e.g. "mikrotik.md").
const DOC_BASE = 'https://github.com/FirdausYudha/DeusWatch/blob/main/docs/'

export default function DocLink({
  file,
  label = 'See documentation',
  className = '',
}: {
  file: string
  label?: string
  className?: string
}) {
  return (
    <a
      href={DOC_BASE + file}
      target="_blank"
      rel="noreferrer"
      className={`inline-flex items-center gap-1 text-xs text-accent transition-colors hover:text-accent hover:underline ${className}`}
    >
      {label}
      <span aria-hidden>â†—</span>
    </a>
  )
}
