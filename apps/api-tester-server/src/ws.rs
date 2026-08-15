//! WebSocket endpoint: streams real-time JSON events (new flows, proxy status,
//! intercept queue changes) to the browser UI over a single `ws://` connection.

use std::sync::Arc;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;

use crate::routes::SharedState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state.ws_tx.clone()))
}

async fn handle_socket(socket: WebSocket, tx: Arc<broadcast::Sender<String>>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = tx.subscribe();

    // Push every server event to this client until the socket closes.
    let push = tokio::spawn(async move {
        while let Ok(text) = rx.recv().await {
            if sender.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    // Drain incoming frames (keeps the connection alive; the client sends none).
    while let Some(Ok(_frame)) = receiver.next().await {}

    push.abort();
}
