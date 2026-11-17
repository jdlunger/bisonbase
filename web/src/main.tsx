import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";

// Passkeys need a domain, never an IP address (localhost is the one exception), so bounce
// loopback IPs (e.g. VS Code's port-forwarded links) to localhost.
if (location.hostname === "127.0.0.1" || location.hostname === "[::1]") {
  location.hostname = "localhost";
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
