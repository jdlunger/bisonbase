// A private node's sign-in page (web/gate.html, served by `gate_page` in src/main.rs): a passkey sign-in,
// and nothing that says what this is. Signing in derives our keys from a passkey and signs an access token
// (see passkey.ts); if the node lets us in, it sets its access cookie, and reloading this page loads the
// app instead. On a claim link (/claim#<token>), signing in claims it too, if it lets us in, and a new
// passkey can be made for it.
import { b58, init } from "../../client/src/core.ts";
import { type PasskeyIds, createPasskey, handOff, identityKey, prfFromPasskey, signIn } from "./passkey.ts";

// Passkeys need a domain, never an IP address (localhost is the one exception).
if (location.hostname === "127.0.0.1" || location.hostname === "[::1]") location.hostname = "localhost";

const signInButton = document.getElementById("sign-in") as HTMLButtonElement;
const newButton = document.getElementById("new-passkey") as HTMLButtonElement;
const message = document.getElementById("message") as HTMLParagraphElement;
const claim = location.pathname === "/claim" ? location.hash.slice(1).split(".")[0] || undefined : undefined;

function say(text: string) {
  message.textContent = text;
  message.hidden = !text;
}

async function enter(get: () => Promise<{ secret: Uint8Array<ArrayBuffer>; ids: PasskeyIds }>) {
  signInButton.disabled = newButton.disabled = true;
  say("");
  try {
    const { secret, ids } = await get();
    const { signKey, pk } = await identityKey(secret);
    const sign = async (data: Uint8Array) => new Uint8Array(await crypto.subtle.sign("Ed25519", signKey, data as Uint8Array<ArrayBuffer>));
    if (await signIn(sign, b58(pk), claim)) {
      handOff(secret, ids);
      location.reload();
      return;
    }
    say(claim ? "This passkey doesn't have access, and the link didn't give it." : "This passkey doesn't have access.");
  } catch (e) {
    say((e as Error).message);
  }
  signInButton.disabled = newButton.disabled = false;
}

signInButton.onclick = () => enter(() => prfFromPasskey());
newButton.onclick = () => enter(createPasskey);
newButton.hidden = !claim;

init().then(
  () => (signInButton.disabled = newButton.disabled = false),
  (e) => say(`Couldn't load: ${e.message}`),
);
