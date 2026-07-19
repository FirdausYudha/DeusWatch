import { QRCodeSVG } from 'qrcode.react'

// Support / donation modal. Saweria is wired now; Ko-fi can be added later once a
// slug is available (leave KOFI_PAGE empty to hide its button).
// The QR is generated locally from the donation page URL (Saweria refuses to be
// embedded in an iframe), so scanning it opens the donate page â€” no external calls.
const SAWERIA_PAGE = 'https://saweria.co/DeusLoVult1'
const KOFI_PAGE = 'https://ko-fi.com/firdausyudha'

export default function SupportModal({ onClose }: { onClose: () => void }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="w-full max-w-sm rounded-2xl border border-border bg-surface p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-fg">
            <span className="text-rose-400">â™¥</span> Support DeusWatch
          </h2>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-md px-2 py-1 text-dim hover:bg-surface-2 hover:text-fg"
          >
            âœ•
          </button>
        </div>
        <p className="mb-5 text-sm text-muted">
          DeusWatch is free &amp; open. If it helps you, a small donation keeps it going â€” thank you! ðŸ™
        </p>

        <div className="space-y-2">
          <a
            href={SAWERIA_PAGE}
            target="_blank"
            rel="noopener noreferrer"
            className="block rounded-lg bg-amber-500 px-4 py-2.5 text-center text-sm font-semibold text-slate-900 transition-colors hover:bg-amber-400"
          >
            Donate via Saweria
          </a>
          {KOFI_PAGE && (
            <a
              href={KOFI_PAGE}
              target="_blank"
              rel="noopener noreferrer"
              className="block rounded-lg bg-sky-500 px-4 py-2.5 text-center text-sm font-semibold text-fg transition-colors hover:bg-sky-400"
            >
              Support on Ko-fi
            </a>
          )}
        </div>

        <div className="mt-5">
          <p className="mb-2 text-center text-xs text-dim">or scan to open the donate page</p>
          <div className="mx-auto w-fit rounded-lg bg-white p-3">
            <QRCodeSVG value={SAWERIA_PAGE} size={200} level="M" />
          </div>
        </div>
      </div>
    </div>
  )
}
