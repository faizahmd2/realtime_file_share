import { FileRoomDurableObject } from './durable-object';

import {
    generateShortId,
    createToken,
    verifyToken,
    getCookie,
    hashPassword,
    verifyPassword,
    generateSecureToken,
    generateFileKey,
    validateFileName
} from './utils';
import dashboardHTML from './dashboard.html';

export { FileRoomDurableObject };

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        env.IS_DEV = url.hostname === 'localhost' || url.hostname === '127.0.0.1';

        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, X-Session-Token',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        try {
            if (path.startsWith('/ws/room/')) {
                const visibleId = decodeURIComponent(path.split('/ws/room/')[1] || '');
                if (!visibleId) return new Response('Room ID required', { status: 400 });

                let doName, username;
                if (visibleId.startsWith('_')) {
                    const payload = await requireAuthCookie(request, env);
                    if (!payload) return new Response('Unauthorized', { status: 401 });
                    username = payload.u;
                    doName = `${username}:${visibleId.slice(1)}`;
                } else {
                    username = 'pub';
                    doName = `${username}:${visibleId}`;
                }

                const id = env.FILE_SHARE_ROOM.idFromName(doName);
                const stub = env.FILE_SHARE_ROOM.get(id);

                const forwarded = new Request(request, {
                    headers: new Headers({
                        ...Object.fromEntries(request.headers),
                        'x-username': username,
                        'x-room': visibleId
                    })
                });

                return stub.fetch(forwarded);
            }

            if (path === '/') {
                let id = url.searchParams.get('id');
                if (!id) {
                    const newId = generateShortId();
                    return Response.redirect(`${url.origin}?id=${newId}`, 302);
                }
                return new Response(dashboardHTML, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders } });
            }

            if (path === '/auth/verify' && request.method === 'POST') {
                const { username, password } = await request.json();
                if (!username || !password) return json({ success: false, error: 'Username and password required' }, 400, corsHeaders);
                const user = await verifyCredentials(env.DB, username, password);
                if (user) {
                    const token = await createToken(env.AUTH_SECRET, username, 7);
                    const headers = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders });
                    const maxAge = 7 * 24 * 60 * 60;
                    let cookie = `auth=${token}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax`;
                    if (!env.IS_DEV) cookie += '; Secure';
                    headers.append('Set-Cookie', cookie);
                    return new Response(JSON.stringify({ success: true }), { status: 200, headers });
                } else {
                    return json({ success: false, error: 'Invalid credentials' }, 401, corsHeaders);
                }
            }

            if (path === '/auth/status' && request.method === 'GET') {
                const idQuery = url.searchParams.get('id');
                const token = getCookie(request, 'auth');
                const payload = token ? await verifyToken(env.AUTH_SECRET, token) : null;
                if (!payload) return json({ loggedIn: false, allowed: idQuery && !idQuery.startsWith('_') }, 200, corsHeaders);
                return json({ loggedIn: true, username: payload.u, allowed: true }, 200, corsHeaders);
            }

            if (path === '/api/init-upload' && request.method === 'POST') {
                return await handleInitUpload(request, env, corsHeaders);
            }
            if (path === '/api/r2-upload/' && request.method === 'PUT') {
            }
            if (path.startsWith('/api/r2-upload/') && request.method === 'PUT') {
                return await handleR2Upload(request, env, corsHeaders);
            }
            if (path === '/api/upload-complete' && request.method === 'POST') {
                return await handleUploadComplete(request, env, corsHeaders, ctx);
            }
            if (path === '/api/files' && request.method === 'GET') {
                return await handleListFiles(request, env, corsHeaders);
            }
            if (path.startsWith('/api/download/') && request.method === 'GET') {
                return await handleDownload(request, env, corsHeaders);
            }
            if (path.startsWith('/api/files/') && request.method === 'DELETE') {
                return await handleDeleteFile(request, env, corsHeaders);
            }
            if (path.startsWith('/api/stats/') && request.method === 'GET') {
                return await handleGetStats(request, env, corsHeaders);
            }

            if (path === '/admin/users/create' && request.method === 'POST') {
                const adminKey = request.headers.get('X-Admin-Key');
                if (adminKey !== env.ADMIN_KEY) {
                    return new Response('Unauthorized', { status: 401 });
                }

                const { username, password } = await request.json();
                if (!username || !password) {
                    return new Response(JSON.stringify({
                        success: false,
                        error: 'Username and password required'
                    }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

                const passwordHash = await hashPassword(password);

                await env.DB.prepare(
                    `INSERT INTO users (username, password_hash, created_at)
          VALUES (?, ?, ?)
          ON CONFLICT(username) DO UPDATE SET 
          password_hash = excluded.password_hash`
                ).bind(username, passwordHash, Date.now()).run();

                return new Response(JSON.stringify({
                    success: true,
                    username
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            return new Response('Not Found', { status: 404, headers: corsHeaders });

        } catch (err) {
            console.error('Worker error:', err);
            return json({ error: err.message }, 500, corsHeaders);
        }
    },

    async scheduled(evt, env, ctx) {
        ctx.waitUntil(cleanupExpiredFiles(env));
    }
};

function json(body, status = 200, headers = {}) {
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

async function requireAuthCookie(request, env) {
    const token = getCookie(request, 'auth');
    if (!token) return null;
    const payload = await verifyToken(env.AUTH_SECRET, token);
    return payload || null;
}

async function verifyCredentials(db, username, password) {
    try {
        const result = await db.prepare('SELECT username, password_hash FROM users WHERE username = ?').bind(username).first();
        if (!result) return null;
        const ok = await verifyPassword(password, result.password_hash);
        return ok ? { username: result.username } : null;
    } catch (e) {
        console.error('verifyCredentials error', e);
        return null;
    }
}

async function resolveVisibleId(request, env, visibleId) {
    if (!visibleId) return { ok: false, errorResponse: json({ error: 'id required' }, 400) };

    if (!visibleId.startsWith('_')) {
        // public room
        const raw = visibleId;
        const username = 'pub';
        return { ok: true, rawId: raw, username, doName: `${username}:${raw}` };
    }

    const payload = await requireAuthCookie(request, env);
    if (!payload) return { ok: false, errorResponse: json({ error: 'Unauthorized' }, 401) };

    const raw = visibleId.slice(1);
    const username = payload.u;
    return { ok: true, rawId: raw, username, doName: `${username}:${raw}` };
}

async function handleInitUpload(request, env, corsHeaders) {
    const body = await request.json().catch(() => ({}));
    const { id: visibleId, fileName, fileSize, expiryMinutes, clientFingerprint } = body;
    if (!visibleId || !fileName || !fileSize || expiryMinutes === undefined || !clientFingerprint) {
        return json({ error: 'Missing required fields' }, 400, corsHeaders);
    }

    const resolved = await resolveVisibleId(request, env, visibleId);
    if (!resolved.ok) return resolved.errorResponse;
    const dbUniqueId = resolved.rawId;
    const owner = resolved.username;

    const maxFileSize = parseInt(env.MAX_FILE_SIZE || '104857600', 10);
    if (fileSize > maxFileSize) return json({ error: `File exceeds maximum ${Math.round(maxFileSize / 1024 / 1024)}MB` }, 400, corsHeaders);
    if (!validateFileName(fileName)) return json({ error: 'Invalid file name' }, 400, corsHeaders);

    const limit = await checkDailyUploadLimit(env.DB, dbUniqueId, owner, fileSize, env);
    if (!limit.allowed) return json({ error: 'Daily upload limit exceeded', quota: limit }, 429, corsHeaders);

    const sessionToken = generateSecureToken();
    const sessionId = crypto.randomUUID();
    const fileKey = generateFileKey(`${owner}:${dbUniqueId}`, fileName, sessionId);
    const now = Date.now();

    await env.DB.prepare(`
    INSERT INTO upload_sessions 
    (session_id, session_token, unique_id, username, file_key, file_name, file_size, expiry_minutes, client_fingerprint, status, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
  `).bind(sessionId, sessionToken, dbUniqueId, owner, fileKey, fileName, fileSize, expiryMinutes, clientFingerprint, now, now + 3600000).run();

    return json({ sessionToken, sessionId, fileKey, expiresAt: now + 3600000 }, 200, corsHeaders);
}

async function handleR2Upload(request, env, corsHeaders) {
    const pathAfter = new URL(request.url).pathname.split('/api/r2-upload/')[1] || '';
    const fileKey = decodeURIComponent(pathAfter);
    const sessionToken = request.headers.get('X-Session-Token');
    if (!sessionToken) return json({ error: 'Session token required' }, 401, corsHeaders);

    const session = await env.DB.prepare('SELECT * FROM upload_sessions WHERE session_token = ? AND file_key = ? AND status = "pending"').bind(sessionToken, fileKey).first();
    if (!session) return json({ error: 'Invalid session' }, 401, corsHeaders);

    if (session.username !== 'pub') {
        const payload = await requireAuthCookie(request, env);
        if (!payload || payload.u !== session.username) return json({ error: 'Unauthorized' }, 401, corsHeaders);
    }

    try {
        await env.R2_BUCKET.put(fileKey, request.body, { httpMetadata: { contentType: 'application/octet-stream' } });
        return json({ success: true }, 200, corsHeaders);
    } catch (err) {
        console.error('R2 put error', err);
        return json({ error: 'Upload failed' }, 500, corsHeaders);
    }
}

async function handleUploadComplete(request, env, corsHeaders, ctx) {
    const sessionToken = request.headers.get('X-Session-Token');
    if (!sessionToken) return json({ error: 'Session token required' }, 401, corsHeaders);

    const session = await env.DB.prepare('SELECT * FROM upload_sessions WHERE session_token = ? AND status = "pending"').bind(sessionToken).first();
    if (!session) return json({ error: 'Invalid session' }, 401, corsHeaders);

    if (session.username !== 'pub') {
        const payload = await requireAuthCookie(request, env);
        if (!payload || payload.u !== session.username) return json({ error: 'Unauthorized' }, 401, corsHeaders);
    }

    const now = Date.now();
    const expireAt = session.expiry_minutes === 0 ? now + (100 * 365 * 24 * 60 * 60 * 1000) : now + (session.expiry_minutes * 60 * 1000);

    await env.DB.prepare(`
    INSERT INTO files (id, unique_id, username, file_key, original_name, size, content_type, expiry_minutes, expire_at, uploaded_at, status, session_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?)
  `).bind(crypto.randomUUID(), session.unique_id, session.username, session.file_key, session.file_name, session.file_size, 'application/octet-stream', session.expiry_minutes, expireAt, now, session.session_id).run();

    await env.DB.prepare('UPDATE upload_sessions SET upload_completed = 1, status = "completed", completed_at = ? WHERE session_id = ?').bind(now, session.session_id).run();

    try {
        const doName = `${session.username}:${session.unique_id}`;
        const id = env.FILE_SHARE_ROOM.idFromName(doName);
        const stub = env.FILE_SHARE_ROOM.get(id);
        
        ctx.waitUntil(stub.fetch(new Request('https://dummy/broadcast', {
            method: 'POST',
            body: JSON.stringify({ type: 'file_uploaded', fileKey: session.file_key, fileName: session.file_name })
        })));
    } catch (err) {
        console.error('broadcast failed', err);
    }

    return json({ success: true, message: 'Upload confirmed' }, 200, corsHeaders);
}

async function handleListFiles(request, env, corsHeaders) {
    const q = new URL(request.url).searchParams;
    const visibleId = q.get('id');
    const resolved = await resolveVisibleId(request, env, visibleId);
    if (!resolved.ok) return resolved.errorResponse;

    const rows = await env.DB.prepare('SELECT id, unique_id, username, file_key, original_name, size, expire_at, uploaded_at, expiry_minutes FROM files WHERE unique_id = ? AND username = ? AND expire_at > ? AND status = "completed" ORDER BY uploaded_at DESC').bind(resolved.rawId, resolved.username, Date.now()).all();

    const limitCheck = await checkDailyUploadLimit(env.DB, resolved.rawId, resolved.username, 0, env);
    return json({ files: rows.results || [], disableUpload: !limitCheck.allowed, quota: limitCheck }, 200, corsHeaders);
}

async function handleDownload(request, env, corsHeaders) {
    const pathAfter = new URL(request.url).pathname;
    const [, , , visibleId, ...rest] = pathAfter.split('/');
    const fileKey = decodeURIComponent(rest.join('/'));
    const resolved = await resolveVisibleId(request, env, visibleId);
    if (!resolved.ok) return resolved.errorResponse;

    const file = await env.DB.prepare('SELECT * FROM files WHERE unique_id = ? AND username = ? AND file_key = ? AND expire_at > ? AND status = "completed"').bind(resolved.rawId, resolved.username, fileKey, Date.now()).first();
    if (!file) return json({ error: 'File not found or expired' }, 404, corsHeaders);

    const obj = await env.R2_BUCKET.get(file.file_key);
    if (!obj) return json({ error: 'File missing in storage' }, 404, corsHeaders);

    return new Response(obj.body, { headers: { 'Content-Type': file.content_type || 'application/octet-stream', 'Content-Disposition': `attachment; filename="${file.original_name}"`, ...corsHeaders } });
}

async function handleDeleteFile(request, env, corsHeaders) {
    const pathAfter = new URL(request.url).pathname;
    const [, , , visibleId, ...rest] = pathAfter.split('/');
    const fileKey = decodeURIComponent(rest.join('/'));
    const resolved = await resolveVisibleId(request, env, visibleId);
    if (!resolved.ok) return resolved.errorResponse;

    const file = await env.DB.prepare('SELECT * FROM files WHERE unique_id = ? AND username = ? AND file_key = ?').bind(resolved.rawId, resolved.username, fileKey).first();
    if (!file) return json({ error: 'File not found' }, 404, corsHeaders);

    await env.R2_BUCKET.delete(file.file_key);
    await env.DB.prepare('DELETE FROM files WHERE unique_id = ? AND username = ? AND file_key = ?').bind(resolved.rawId, resolved.username, fileKey).run();
    await env.DB.prepare('UPDATE upload_sessions SET status = "deleted" WHERE session_id = ?').bind(file.session_id).run();

    try {
        const doName = `${resolved.username}:${resolved.rawId}`;
        const id = env.FILE_SHARE_ROOM.idFromName(doName);
        const stub = env.FILE_SHARE_ROOM.get(id);
        stub.fetch(new Request('https://dummy/broadcast', { method: 'POST', body: JSON.stringify({ type: 'file_deleted', fileKey }) })).catch(() => { });
    } catch (err) {
        console.error('broadcast delete err', err);
    }

    return json({ success: true, message: 'File deleted' }, 200, corsHeaders);
}

async function handleGetStats(request, env, corsHeaders) {
    const visibleId = request.url.split('/api/stats/')[1];
    const resolved = await resolveVisibleId(request, env, visibleId);
    if (!resolved.ok) return resolved.errorResponse;
    const limitCheck = await checkDailyUploadLimit(env.DB, resolved.rawId, resolved.username, 0, env);
    return json({ quota: limitCheck, config: { maxFileSize: parseInt(env.MAX_FILE_SIZE || 104857600) } }, 200, corsHeaders);
}

async function checkDailyUploadLimit(db, rawId, username, newSize, env) {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const todayTs = today.getTime(), tomorrow = todayTs + 86400000;
    // const r = await db.prepare('SELECT COALESCE(SUM(size),0) as total_size, COUNT(*) as file_count FROM files WHERE unique_id = ? AND username = ? AND uploaded_at >= ? AND uploaded_at < ? AND status = "completed"').bind(rawId, username, todayTs, tomorrow).first();
    const r = await db.prepare('SELECT COALESCE(SUM(file_size),0) as total_size, COUNT(*) as file_count FROM upload_sessions WHERE unique_id = ? AND username = ? AND upload_completed = 1 AND completed_at >= ? AND completed_at < ?').bind(rawId, username, todayTs, tomorrow).first();
    const current = r?.total_size || 0;
    const fileCount = r?.file_count || 0;
    const dailyLimit = parseInt(env.DAILY_UPLOAD_LIMIT || '0', 10);
    const maxFiles = parseInt(env.MAX_FILES_PER_ID || '100', 10);
    const newTotal = current + newSize;
    const newCount = fileCount + (newSize > 0 ? 1 : 0);
    return { allowed: (dailyLimit === 0 ? true : newTotal <= dailyLimit) && newCount <= maxFiles, used: current, limit: dailyLimit, remaining: Math.max(0, dailyLimit - current), fileCount, maxFiles, usagePercentage: dailyLimit > 0 ? Math.round((current / dailyLimit) * 100) : 0 };
}

async function cleanupExpiredFiles(env) {
    try {
        const now = Date.now();
        const expired = await env.DB.prepare('SELECT file_key, session_id FROM files WHERE expire_at < ? AND expiry_minutes > 0').bind(now).all();
        for (const row of expired.results || []) {
            try { 
                await env.R2_BUCKET.delete(row.file_key); 
                await env.DB.prepare('DELETE FROM files WHERE file_key = ?').bind(row.file_key).run(); 
                await env.DB.prepare('UPDATE upload_sessions SET status = "expired" WHERE session_id = ?').bind(row.session_id).run();
            } catch (e) { 
                console.error('cleanup err', e);
            }
        }
        // await env.DB.prepare('DELETE FROM upload_sessions WHERE expires_at < ? OR (created_at < ? AND upload_completed = 0)').bind(now, now - 3600000).run();
    } catch (e) { console.error('cleanup error', e); }
}