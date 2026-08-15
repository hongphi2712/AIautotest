// WebSocket client: receives real-time events from the axum backend and
// re-dispatches them as `app:ws-<type>` DOM events for the views.
// Reconnects automatically with a short backoff; the REST poll fallback covers
// any gap while disconnected.

let socket = null;
let reconnectTimer = null;

export function connectWs() {
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    return;
  }
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  try {
    socket = new WebSocket(`${proto}://${location.host}/ws`);
  } catch {
    reconnectTimer = setTimeout(connectWs, 3000);
    return;
  }
  socket.onmessage = (event) => {
    let data;
    try { data = JSON.parse(event.data); } catch { return; }
    if (!data || !data.type) return;
    window.dispatchEvent(new CustomEvent('app:ws-' + data.type, { detail: data }));
  };
  socket.onclose = () => {
    socket = null;
    reconnectTimer = setTimeout(connectWs, 3000);
  };
  socket.onerror = () => {
    try { socket.close(); } catch { /* noop */ }
  };
}
