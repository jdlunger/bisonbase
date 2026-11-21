import { useState } from "react";
import { type User, connectApp, decodeIdOrThrow, deletePost, myDelegations } from "./api.ts";
import { type ConnectRequest, b58, connectReturnUrl, parseConnectRequest, unb58 } from "../../client/src/index.ts";
import { type Run, danger, hl, primary, useLoad } from "./ui.ts";

/** /connect#key=…&name=…&return=…: an app asking to sign records for us (see "the connect flow" in
 * client/src/signer.ts). Agreeing writes a delegation, then sends us back to the app. Below, the apps
 * we've let sign for us, to revoke. */
export function ConnectPage({ me, busy, run }: { me: User | null; busy: boolean; run: Run }) {
  const [tick, setTick] = useState(0);
  let req: ConnectRequest | null = null;
  let error = "";
  if (location.hash.length > 1) {
    try {
      req = parseConnectRequest(location.hash);
    } catch (e) {
      error = (e as Error).message;
    }
  }
  const { data: apps } = useLoad(me ? myDelegations : null, [me?.pubkey], tick);

  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-bold tracking-tight">Connect an app</h1>
      {error && <p className="text-red-700">This link is broken: {error}</p>}
      {req && (
        <div className="space-y-3 rounded-lg p-4 ring-1 ring-gray-200">
          <p>
            <b>{req.name || "An app"}</b>, at <code className="font-mono text-sm">{new URL(req.returnTo).host}</code>, asks to sign records for you:
          </p>
          <ul className="list-disc pl-6 text-sm">
            <li>Of types: {req.types?.length ? req.types.map((t) => <code key={t} className="mr-1 font-mono">{t}</code>) : <b>any</b>}</li>
            <li>At or under: {req.paths?.length ? req.paths.map((p) => <code key={p} className="mr-1 font-mono">{p}</code>) : <b>anywhere you may write</b>}</li>
            <li>{req.expires ? `Until ${new Date(req.expires).toLocaleString()}` : "Until you revoke it"}</li>
          </ul>
          <p className="text-xs text-gray-500">
            What it signs counts as yours. It can never change your delegations or your encryption key, nor read your encrypted docs. If you
            revoke it, people stop trusting everything it signed for you. Its key: <code className="font-mono break-all">{b58(req.key)}</code>
          </p>
          {me ? (
            <button
              className={primary}
              disabled={busy}
              onClick={run(async () => {
                const hash = await connectApp(req!);
                location.href = connectReturnUrl(req!.returnTo, { user: decodeIdOrThrow(me.pubkey), delegation: unb58(hash)!, node: location.origin });
              })}
            >
              Let it sign for <span className={hl(me.phrase)}>{me.phrase}</span>
            </button>
          ) : (
            <p>Sign in first (top right), with the keys it should sign for.</p>
          )}
        </div>
      )}

      {me && (
        <div className="space-y-2">
          <h2 className="font-semibold">Apps you've connected on this node</h2>
          {!apps ? (
            <p className="text-sm text-gray-500">Loading…</p>
          ) : !apps.length ? (
            <p className="text-sm text-gray-500">None.</p>
          ) : (
            <ul className="divide-y divide-gray-200 rounded-lg ring-1 ring-gray-200">
              {apps.map((a) => (
                <li key={a.root} className="flex items-center justify-between gap-2 p-3 text-sm">
                  <span>
                    <b>{a.delegate!.name || "An app"}</b>{" "}
                    <span className="text-gray-500">
                      · {a.delegate!.types?.join(", ") ?? "any type"} · {a.delegate!.paths?.join(" ") ?? "anywhere"}
                      {a.delegate!.expires && ` · until ${new Date(a.delegate!.expires).toLocaleString()}`}
                    </span>
                  </span>
                  <button
                    className={danger}
                    disabled={busy}
                    onClick={run(async () => {
                      await deletePost(a);
                      setTick((t) => t + 1);
                    })}
                  >
                    Revoke
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
