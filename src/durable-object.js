export class FileRoomDurableObject {
    constructor(state, env) {
        this.state = state;
        this.env = env;
        this.sockets = new Set();
        this.MAX_RECENT = 20;
    }

    _safeSend(ws, msg) {
        try {
            if (ws && ws.readyState === 1) {
                ws.send(msg);
                return true;
            }
        } catch (e) {
            // ignore send errors
        }
        return false;
    }

    _broadcastJSON(obj) {
        const payload = JSON.stringify(obj);
        for (const ws of Array.from(this.sockets)) {
            const ok = this._safeSend(ws, payload);
            if (!ok) {
                this.sockets.delete(ws);
                try { ws.close && ws.close(); } catch (e) { }
            }
        }
    }

    async _handleWebSocketUpgrade(request) {
        const pair = new WebSocketPair();
        const [clientSide, serverSide] = Object.values(pair);

        serverSide.accept();

        this.sockets.add(serverSide);

        serverSide.addEventListener('message', (evt) => {
            try {
                const msg = typeof evt.data === 'string' ? evt.data : null;
                if (msg === 'ping') {
                    serverSide.send(JSON.stringify({ type: 'pong' }));
                }
            } catch (e) { /* ignore */ }
        });

        serverSide.addEventListener('close', () => {
            this.sockets.delete(serverSide);
        });

        serverSide.addEventListener('error', () => {
            this.sockets.delete(serverSide);
            try { serverSide.close(); } catch (e) { }
        });

        return new Response(null, { status: 101, webSocket: clientSide });
    }

    async _handleBroadcast(request) {
        let payload;
        try {
            payload = await request.json();
        } catch (e) {
            return new Response('Bad JSON', { status: 400 });
        }
        if (!payload || typeof payload.type !== 'string') {
            return new Response('Missing type', { status: 400 });
        }

        this._broadcastJSON(payload);
        return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }

    async fetch(request) {
        const url = new URL(request.url);
        const pathname = url.pathname;

        if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
            return await this._handleWebSocketUpgrade(request);
        }

        if (pathname.endsWith('/broadcast') && request.method === 'POST') {
            return await this._handleBroadcast(request);
        }

        return new Response('Not found', { status: 404 });
    }
}
