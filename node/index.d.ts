/** Every option is optional. */
export interface StartOptions {
  /** Port to listen on (on 127.0.0.1); 0 picks a free one. Default 8080. */
  port?: number
  /** Directory for system.db and user files. Default "./data". */
  dataDir?: string
  /**
   * Log filter in RUST_LOG syntax, e.g. "bisonbase=debug,tower_http=info", or "off".
   * Default "bisonbase=info". Only the first `start()` in a process sets up logging.
   */
  log?: string
}

export declare class Server implements AsyncDisposable {
  private constructor()
  /** Public origin of the web UI and API, e.g. "http://localhost:8080". */
  readonly url: string
  /** Address the listener is bound to. */
  readonly host: string
  /** Port the listener is bound to (useful with `port: 0`). */
  readonly port: number
  /** One-time admin signup link if the data directory had no users, else null. */
  readonly setupUrl: string | null
  /** Let the process exit even if the server is still running. */
  unref(): this
  /** Undo `unref()`. */
  ref(): this
  /** Stop accepting connections and wait for in-flight requests. Safe to call twice. */
  close(): Promise<void>
  [Symbol.asyncDispose](): Promise<void>
}

/** Start a bisonbase server in this process. Resolves once it is listening. */
export declare function start(options?: StartOptions): Promise<Server>
