// Support / donation modal. Saweria is wired now; Ko-fi can be added later once a
// slug is available (leave KOFI_PAGE empty to hide its button).
const SAWERIA_PAGE = 'https://saweria.co/DeusLoVult1'
const SAWERIA_QR = 'https://saweria.co/widgets/qr?streamKey=a3662ae6b331bb4049033c8e421a1881'
const KOFI_PAGE = '' // e.g. 'https://ko-fi.com/<slug>'

export default function SupportModal({ onClose }: { onClose: () => void }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            <span className="text-rose-400">♥</span> Support DeusWatch
          </h2>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-md px-2 py-1 text-slate-500 hover:bg-slate-800 hover:text-slate-200"
          >
            ✕
          </button>
        </div>
        <p className="mb-5 text-sm text-slate-400">
          DeusWatch is free &amp; open. If it helps you, a small donation keeps it going — thank you! 🙏
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
              className="block rounded-lg bg-sky-500 px-4 py-2.5 text-center text-sm font-semibold text-white transition-colors hover:bg-sky-400"
            >
              Support on Ko-fi
            </a>
          )}
        </div>

        <div className="mt-5">
          <p className="mb-2 text-center text-xs text-slate-500">or scan the QR</p>
          <div className="mx-auto h-56 w-56 overflow-hidden rounded-lg bg-white">
            <iframe src={SAWERIA_QR} title="Saweria donation QR" className="h-full w-full border-0" />
          </div>
          <a
            href={SAWERIA_QR}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-2 block text-center text-xs text-slate-500 hover:text-slate-300"
          >
            QR not showing? Open it in a new tab
          </a>
        </div>
      </div>
    </div>
  )
}
