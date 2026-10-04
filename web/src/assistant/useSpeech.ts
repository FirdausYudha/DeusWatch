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

// voiceScore ranks the installed voices, best first.
//
// This matters more than any other setting. Every OS ships a cheap formant synthesiser alongside
// its good voices, and picking "the first one matching the language" lands on the cheap one about
// half the time, which is what makes the result sound like a 1998 train announcement. Network and
// "Natural"/"Neural" voices are the modern ones; local eSpeak-class voices are the fallback.
function voiceScore(v: SpeechSynthesisVoice, lang: string): number {
  let s = 0
  if (v.lang.toLowerCase().startsWith(lang.slice(0, 2).toLowerCase())) s += 100
  if (v.lang.toLowerCase() === lang.toLowerCase()) s += 20
  const n = v.name.toLowerCase()
  if (/natural|neural/.test(n)) s += 40
  if (/google/.test(n)) s += 25
  if (/microsoft/.test(n)) s += 10
  if (!v.localService) s += 15 // network voices are the good ones on most platforms
  if (/espeak|compact|festival/.test(n)) s -= 40
  return s
}

// Spoken text is not written text. Markdown punctuation is read out literally by every engine
// ("asterisk asterisk high severity"), so it goes before the utterance does.
function forSpeech(text: string): string {
  return text
    .replace(/```[\s\S]*?```/g, ' code block ')
    .replace(/[*_`#>]/g, '')
    .replace(/\s*\n\s*/g, '. ')
    .replace(/\.{2,}/g, '.')
    .replace(/\s{2,}/g, ' ')
    .trim()
}

/** useSpeaker reads replies aloud. Synthesis is local to the browser, so nothing leaves the host. */
export function useSpeaker(voiceURI: string, rate: number) {
  const [speaking, setSpeaking] = useState(false)
  const [voices, setVoices] = useState<SpeechSynthesisVoice[]>([])
  const supported = typeof window !== 'undefined' && 'speechSynthesis' in window

  // getVoices() is empty until the engine has loaded them, and on Chrome that happens after the
  // first paint, so the list has to be rebuilt on voiceschanged or the picker renders empty.
  useEffect(() => {
    if (!supported) return
    const load = () => {
      const lang = uiLang()
      setVoices([...window.speechSynthesis.getVoices()].sort((a, b) => voiceScore(b, lang) - voiceScore(a, lang)))
    }
    load()
    window.speechSynthesis.addEventListener('voiceschanged', load)
    return () => window.speechSynthesis.removeEventListener('voiceschanged', load)
  }, [supported])

  const cancel = useCallback(() => {
    if (!supported) return
    window.speechSynthesis.cancel()
    setSpeaking(false)
  }, [supported])

  const speak = useCallback(
    (text: string) => {
      const say = forSpeech(text)
      if (!supported || !say) return
      // Replace rather than queue: an operator asking a second question wants the new answer, not
      // the tail of the previous one.
      window.speechSynthesis.cancel()
      const u = new SpeechSynthesisUtterance(say)
      u.lang = uiLang()
      const chosen = voices.find((v) => v.voiceURI === voiceURI) ?? voices[0]
      if (chosen) {
        u.voice = chosen
        u.lang = chosen.lang // a voice speaking the wrong lang tag is mispronounced
      }
      u.rate = rate
      // A touch below the default flattens the robotic over-brightness most engines default to.
      u.pitch = 0.95
      u.onend = () => setSpeaking(false)
      u.onerror = () => setSpeaking(false)
      setSpeaking(true)
      window.speechSynthesis.speak(u)
    },
    [supported, voices, voiceURI, rate],
  )

  // Chrome keeps speaking after the tab navigates away unless it is cancelled explicitly.
  useEffect(() => {
    if (!supported) return
    return () => window.speechSynthesis.cancel()
  }, [supported])

  return { supported, speaking, speak, cancel, voices }
}

/** True in Chrome and Edge, where recognition audio is sent to Google. Shown next to the mic. */
export function dictationSendsAudioOffHost(): boolean {
  return !!recognitionCtor()
}
