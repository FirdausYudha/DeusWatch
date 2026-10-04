import { useCallback, useEffect, useRef, useState } from 'react'

// Browser speech for the assistant (ADR 0003, phase 3). Both halves are Web APIs: no new service
// to host, no model to ship, and synthesis works offline on most operating systems.
//
// PRIVACY, and it is not a footnote: in Chrome, speech RECOGNITION streams the microphone to
// Google's servers. Synthesis does not. On a self-hosted security product that asymmetry matters,
// so the microphone is opt-in per session, never starts on its own, and the UI says where the audio
// goes. Self-hosted Whisper + Piper is the replacement path if that is unacceptable.

// Minimal shapes for the Web Speech API, which is not in TypeScript's DOM lib because it has never
// left draft status. Only the members used here are declared.
type SpeechRecognitionAlternative = { transcript: string }
type SpeechRecognitionResult = { 0: SpeechRecognitionAlternative; isFinal: boolean; length: number }
type SpeechRecognitionEvent = { resultIndex: number; results: { length: number } & Record<number, SpeechRecognitionResult> }
type SpeechRecognitionLike = {
  lang: string
  continuous: boolean
  interimResults: boolean
  start: () => void
  stop: () => void
  abort: () => void
  onresult: ((e: SpeechRecognitionEvent) => void) | null
  onerror: ((e: { error: string }) => void) | null
  onend: (() => void) | null
}
type SpeechRecognitionCtor = new () => SpeechRecognitionLike

function recognitionCtor(): SpeechRecognitionCtor | null {
  const w = window as unknown as Record<string, unknown>
  return (w.SpeechRecognition ?? w.webkitSpeechRecognition ?? null) as SpeechRecognitionCtor | null
}

// The operator's own locale drives both halves. Guessing a language from the text would be a
// coin flip on short messages, and getting it wrong makes synthesis unintelligible rather than
// merely accented.
function uiLang(): string {
  return navigator.language || 'en-US'
}

/** Why the microphone is unavailable, or "" when it works. Rendered to the user as-is. */
function dictationBlocker(): string {
  if (!window.isSecureContext) return 'the microphone needs HTTPS (or localhost)'
  if (!recognitionCtor()) return 'this browser has no speech recognition (Chrome and Edge do)'
  return ''
}

/**
 * useDictation turns speech into text. The transcript is handed back for the caller to put in the
 * composer rather than sent automatically: recognition misreads addresses often enough that
 * "block 45.134.26.9" is worth a glance before it becomes a confirmation card.
 */
export function useDictation(onTranscript: (text: string) => void) {
  const [listening, setListening] = useState(false)
  const [error, setError] = useState('')
  const ref = useRef<SpeechRecognitionLike | null>(null)
  const cbRef = useRef(onTranscript)
  cbRef.current = onTranscript

  const blocker = dictationBlocker()

  const stop = useCallback(() => {
    ref.current?.stop()
    setListening(false)
  }, [])

  const start = useCallback(() => {
    if (blocker || ref.current) return
    const Ctor = recognitionCtor()
    if (!Ctor) return
    setError('')
    const rec = new Ctor()
    rec.lang = uiLang()
    rec.continuous = false
    rec.interimResults = true
    let finalText = ''
    rec.onresult = (e) => {
      let interim = ''
      for (let i = e.resultIndex; i < e.results.length; i++) {
        const r = e.results[i]
        if (r.isFinal) finalText += r[0].transcript
        else interim += r[0].transcript
      }
      // Interim results are shown too, so the operator can see it is hearing something and stop
      // early when it is clearly mishearing.
      cbRef.current((finalText + interim).trim())
    }
    rec.onerror = (e) => {
      setError(
        e.error === 'not-allowed'
          ? 'microphone permission denied'
          : e.error === 'no-speech'
            ? ''
            : `microphone: ${e.error}`,
      )
    }
    rec.onend = () => {
      ref.current = null
      setListening(false)
    }
    ref.current = rec
    try {
      rec.start()
      setListening(true)
    } catch {
      ref.current = null
      setError('could not start the microphone')
    }
  }, [blocker])

  // Never leave the microphone open behind a closed panel.
  useEffect(() => () => ref.current?.abort(), [])

  return { listening, error, blocker, start, stop, toggle: () => (listening ? stop() : start()) }
}

/** useSpeaker reads replies aloud. Synthesis is local to the browser, so nothing leaves the host. */
export function useSpeaker() {
  const [speaking, setSpeaking] = useState(false)
  const supported = typeof window !== 'undefined' && 'speechSynthesis' in window

  const cancel = useCallback(() => {
    if (!supported) return
    window.speechSynthesis.cancel()
    setSpeaking(false)
  }, [supported])

  const speak = useCallback(
    (text: string) => {
      const say = text.trim()
      if (!supported || !say) return
      // Replace rather than queue: an operator asking a second question wants the new answer, not
      // the tail of the previous one.
      window.speechSynthesis.cancel()
      const u = new SpeechSynthesisUtterance(say)
      u.lang = uiLang()
      // getVoices() is populated asynchronously and is often empty on the first call; when it is,
      // leaving voice unset lets the engine pick by lang, which is the sane fallback.
      const match = window.speechSynthesis.getVoices().find((v) => v.lang.startsWith(u.lang.slice(0, 2)))
      if (match) u.voice = match
      u.onend = () => setSpeaking(false)
      u.onerror = () => setSpeaking(false)
      setSpeaking(true)
      window.speechSynthesis.speak(u)
    },
    [supported],
  )

  // Chrome keeps speaking after the tab navigates away unless it is cancelled explicitly.
  useEffect(() => {
    if (!supported) return
    return () => window.speechSynthesis.cancel()
  }, [supported])

  return { supported, speaking, speak, cancel }
}

/** True in Chrome and Edge, where recognition audio is sent to Google. Shown next to the mic. */
export function dictationSendsAudioOffHost(): boolean {
  return !!recognitionCtor()
}
