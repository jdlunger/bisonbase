// Following a server-sent event stream with fetch (EventSource can't send an Authorization
// header), reconnecting with backoff until stopped.

export interface WatchOptions {
  /** Open the stream. A failed response or a thrown error is retried, unless `fatal` says not to. */
  open(signal: AbortSignal): Promise<Response>
  /** Whether an error thrown by `open` means stop for good (e.g. signed out). */
  fatal?(error: unknown): boolean
  onEvent(event: string, data: unknown): void
  /** Connected (true) or lost (false). */
  onLive?(live: boolean): void
}

const MIN_DELAY = 500
const MAX_DELAY = 30_000

/** Start following a stream. Returns a function that stops. */
export function watch(opts: WatchOptions): () => void {
  const ctrl = new AbortController()
  const { signal } = ctrl
  void (async () => {
    let delay = MIN_DELAY
    while (!signal.aborted) {
      let res: Response | null = null
      try {
        res = await opts.open(signal)
      } catch (e) {
        if (signal.aborted || opts.fatal?.(e)) return
        // A network error: retry below.
      }
      if (res?.ok && res.body) {
        try {
          for await (const [event, data] of events(res.body, signal)) {
            if (event === 'ready') {
              delay = MIN_DELAY
              opts.onLive?.(true)
            }
            opts.onEvent(event, data)
          }
        } catch {
          // Dropped; reconnect below.
        } finally {
          opts.onLive?.(false)
        }
      } else {
        await res?.body?.cancel().catch(() => {})
      }
      await sleep(delay * (0.5 + Math.random()), signal)
      delay = Math.min(delay * 2, MAX_DELAY)
    }
  })()
  return () => ctrl.abort()
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms)
    // In Node, don't keep the process alive just for this.
    ;(timer as { unref?: () => void }).unref?.()
    signal.addEventListener('abort', done, { once: true })
    function done() {
      clearTimeout(timer)
      signal.removeEventListener('abort', done)
      resolve()
    }
  })
}

/** Parse a text/event-stream body into (event, parsed JSON data) pairs. */
export async function* events(body: ReadableStream<Uint8Array>, signal?: AbortSignal): AsyncGenerator<[string, unknown]> {
  const reader = body.getReader()
  const stop = () => void reader.cancel().catch(() => {})
  signal?.addEventListener('abort', stop, { once: true })
  const decoder = new TextDecoder()
  let buf = ''
  try {
    while (true) {
      const { value, done } = await reader.read()
      if (done) return
      buf += decoder.decode(value, { stream: true })
      let end: number
      while ((end = buf.search(/\r?\n\r?\n/)) >= 0) {
        const block = buf.slice(0, end)
        buf = buf.slice(end).replace(/^\r?\n\r?\n/, '')
        let event = 'message'
        const data: string[] = []
        for (const line of block.split(/\r?\n/)) {
          if (line.startsWith(':')) continue // comment (keep-alive)
          const colon = line.indexOf(':')
          const field = colon < 0 ? line : line.slice(0, colon)
          const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '')
          if (field === 'event') event = value
          else if (field === 'data') data.push(value)
        }
        if (data.length) yield [event, JSON.parse(data.join('\n'))]
      }
    }
  } finally {
    signal?.removeEventListener('abort', stop)
    reader.releaseLock()
  }
}
