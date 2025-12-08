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
      if (path === '/' || path === '/dashboard') {
        let id = url.searchParams.get('id');

        if (!id) {
          const newId = generateShortId();
          return Response.redirect(`${url.origin}/dashboard?id=${newId}`, 302);
        }

        // Private link if id starts with "_"
        if (id.startsWith('_')) {
          const payload = await requireAuthCookie(request, env);
          if (!payload) {
            return new Response('Unauthorized', { status: 401, headers: corsHeaders });
          }
        }

        return new Response(dashboardHTML, {
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            ...corsHeaders
          }
        });
      }

      // -------- Auth endpoints (shared with editor) --------

      if (path === '/auth/verify' && request.method === 'POST') {
        const { username, password } = await request.json();

        if (!username || !password) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Username and password required'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        const user = await verifyCredentials(env.DB, username, password);

        if (user) {
          const token = await createToken(env.AUTH_SECRET, username, 7);

          const headers = new Headers({
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            ...corsHeaders
          });

          const maxAge = 7 * 24 * 60 * 60;
          let cookie = `auth=${token}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax`;
          if (!env.IS_DEV) {
            cookie += '; Secure';
          }
          headers.append('Set-Cookie', cookie);

          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers
          });
        } else {
          return new Response(JSON.stringify({
            success: false,
            error: 'Invalid credentials'
          }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      if (path === '/auth/status' && request.method === 'GET') {
        const token = getCookie(request, 'auth');
        const payload = token ? await verifyToken(env.AUTH_SECRET, token) : null;

        if (!payload) {
          return new Response(JSON.stringify({ loggedIn: false }), {
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        return new Response(JSON.stringify({
          loggedIn: true,
          username: payload.u
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // Admin helper: create/update user
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
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        const passwordHash = await hashPassword(password);

        await env.DB.prepare(
          `INSERT INTO users (username, password_hash, created_at)
           VALUES (?, ?, ?)
           ON CONFLICT(username) DO UPDATE SET 
             password_hash = excluded.password_hash`
        ).bind(username, passwordHash, Date.now()).run();

        return new Response(JSON.stringify({ success: true, username }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // -------- Health check --------

      if (path === '/health') {
        return new Response(JSON.stringify({
          status: 'healthy',
          timestamp: new Date().toISOString(),
          config: {
            maxFileSize: env.MAX_FILE_SIZE,
            dailyLimit: env.DAILY_UPLOAD_LIMIT,
            maxFiles: env.MAX_FILES_PER_ID
          }
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // -------- File API (D1 + R2) --------

      // Init upload
      if (path === '/api/init-upload' && request.method === 'POST') {
        return await handleInitUpload(request, env, corsHeaders);
      }

      // Upload credentials (not used in your simple PUT path,
      // but kept for compatibility / future)
      if (path === '/api/upload-credentials' && request.method === 'POST') {
        return await handleUploadCredentials(request, env, corsHeaders);
      }

      // Complete upload (store metadata, mark session complete)
      if (path === '/api/upload-complete' && request.method === 'POST') {
        return await handleUploadComplete(request, env, corsHeaders);
      }

      // List files for a id
      if (path === '/api/files' && request.method === 'GET') {
        return await handleListFiles(request, env, corsHeaders);
      }

      // Download file
      if (path.startsWith('/api/download/') && request.method === 'GET') {
        return await handleDownload(request, env, corsHeaders);
      }

      // Delete file
      if (path.startsWith('/api/files/') && request.method === 'DELETE') {
        return await handleDeleteFile(request, env, corsHeaders);
      }

      // Get quota / stats
      if (path.startsWith('/api/stats/') && request.method === 'GET') {
        return await handleGetStats(request, env, corsHeaders);
      }

      // Direct PUT to R2 via Worker
      if (path.startsWith('/api/r2-upload/') && request.method === 'PUT') {
        return await handleR2Upload(request, env, corsHeaders);
      }

      return new Response('Not Found', { status: 404, headers: corsHeaders });

    } catch (error) {
      console.error('Worker error:', error);
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  },

  // Scheduled cleanup of expired files
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanupExpiredFiles(env));
  }
};

// ------------- Auth helpers -------------

async function requireAuthCookie(request, env) {
  const token = getCookie(request, 'auth');
  if (!token) return null;
  const payload = await verifyToken(env.AUTH_SECRET, token);
  return payload || null;
}

async function verifyCredentials(db, username, password) {
  try {
    const result = await db.prepare(
      'SELECT username, password_hash FROM users WHERE username = ?'
    ).bind(username).first();

    if (!result) return null;

    const isValid = await verifyPassword(password, result.password_hash);
    if (isValid) {
      return { username: result.username };
    }
    return null;
  } catch (error) {
    console.error('Auth error:', error);
    return null;
  }
}

// ------------- File handlers -------------

async function handleInitUpload(request, env, corsHeaders) {
  const body = await request.json();
  const { id, fileName, fileSize, expiryMinutes, clientFingerprint } = body;

  if (!id || !fileName || !fileSize || !expiryMinutes || !clientFingerprint) {
    return new Response(JSON.stringify({ error: 'Missing required fields' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // Private rooms: require auth if id starts with "_"
  if (id.startsWith('_')) {
    const payload = await requireAuthCookie(request, env);
    if (!payload) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  const maxFileSize = parseInt(env.MAX_FILE_SIZE);
  if (fileSize > maxFileSize) {
    return new Response(JSON.stringify({
      error: `File size exceeds maximum of ${Math.round(maxFileSize / 1024 / 1024)}MB`
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  if (!validateFileName(fileName)) {
    return new Response(JSON.stringify({ error: 'Invalid file name or type' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // Daily quota check
  const limitCheck = await checkDailyUploadLimit(env.DB, id, fileSize, env);
  if (!limitCheck.allowed) {
    return new Response(JSON.stringify({
      error: 'Daily upload limit exceeded',
      quota: limitCheck
    }), {
      status: 429,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // Create upload session
  const sessionToken = generateSecureToken();
  const sessionId = crypto.randomUUID();
  const fileKey = generateFileKey(id, fileName, sessionId);
  const now = Date.now();

  await env.DB.prepare(`
    INSERT INTO upload_sessions 
    (session_id, session_token, unique_id, file_key, file_name, file_size, 
     expiry_minutes, client_fingerprint, status, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
  `).bind(
    sessionId, sessionToken, id, fileKey, fileName, fileSize,
    expiryMinutes, clientFingerprint, now, now + 3600000
  ).run();

  return new Response(JSON.stringify({
    sessionToken,
    sessionId,
    fileKey,
    expiresAt: now + 3600000
  }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleUploadCredentials(request, env, corsHeaders) {
  const sessionToken = request.headers.get('X-Session-Token');
  if (!sessionToken) {
    return new Response(JSON.stringify({ error: 'Session token required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const session = await env.DB.prepare(
    'SELECT * FROM upload_sessions WHERE session_token = ? AND status = "pending" AND expires_at > ?'
  ).bind(sessionToken, Date.now()).first();

  if (!session) {
    return new Response(JSON.stringify({ error: 'Invalid or expired session' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // Extra safety: require auth for private IDs
  if (session.unique_id.startsWith('_')) {
    const payload = await requireAuthCookie(request, env);
    if (!payload) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  const url = new URL(request.url);
  const body = await request.json();
  const contentType = body.contentType || 'application/octet-stream';

  // Using worker proxy instead of presigned URL
  return new Response(JSON.stringify({
    uploadUrl: `${url.origin}/api/r2-upload/${session.file_key}`,
    fileKey: session.file_key,
    sessionToken
  }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleUploadComplete(request, env, corsHeaders) {
  const sessionToken = request.headers.get('X-Session-Token');
  if (!sessionToken) {
    return new Response(JSON.stringify({ error: 'Session token required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const session = await env.DB.prepare(
    'SELECT * FROM upload_sessions WHERE session_token = ? AND status = "pending"'
  ).bind(sessionToken).first();

  if (!session) {
    return new Response(JSON.stringify({ error: 'Invalid session' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // Private -> auth
  if (session.unique_id.startsWith('_')) {
    const payload = await requireAuthCookie(request, env);
    if (!payload) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  const now = Date.now();
  const expireAt = now + (session.expiry_minutes * 60 * 1000);

  await env.DB.prepare(`
    INSERT INTO files 
    (id, unique_id, file_key, original_name, size, content_type, 
     expiry_minutes, expire_at, uploaded_at, status, session_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?)
  `).bind(
    crypto.randomUUID(),
    session.unique_id,
    session.file_key,
    session.file_name,
    session.file_size,
    'application/octet-stream',
    session.expiry_minutes,
    expireAt,
    now,
    session.session_id
  ).run();

  await env.DB.prepare(
    'UPDATE upload_sessions SET upload_completed = 1, status = "completed", completed_at = ? WHERE session_id = ?'
  ).bind(now, session.session_id).run();

  return new Response(JSON.stringify({
    success: true,
    message: 'Upload confirmed'
  }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleListFiles(request, env, corsHeaders) {
  const url = new URL(request.url);
  const id = url.searchParams.get('id');

  if (!id) {
    return new Response(JSON.stringify({ error: 'id required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  if (id.startsWith('_')) {
    const payload = await requireAuthCookie(request, env);
    if (!payload) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  const now = Date.now();
  const files = await env.DB.prepare(
    'SELECT id, unique_id, file_key, original_name, size, expire_at, uploaded_at FROM files WHERE unique_id = ? AND expire_at > ? AND status = "completed" ORDER BY uploaded_at DESC'
  ).bind(id, now).all();

  const limitCheck = await checkDailyUploadLimit(env.DB, id, 0, env);

  return new Response(JSON.stringify({
    files: files.results || [],
    disableUpload: !limitCheck.allowed,
    quota: limitCheck
  }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleDownload(request, env, corsHeaders) {
  const url = new URL(request.url);
  const parts = url.pathname.split('/');
  const id = parts[3];
  const fileKey = decodeURIComponent(parts[4]);

  if (id.startsWith('_')) {
    const payload = await requireAuthCookie(request, env);
    if (!payload) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  const file = await env.DB.prepare(
    'SELECT * FROM files WHERE unique_id = ? AND file_key = ? AND expire_at > ? AND status = "completed"'
  ).bind(id, fileKey, Date.now()).first();

  if (!file) {
    return new Response(JSON.stringify({ error: 'File not found or expired' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const object = await env.R2_BUCKET.get(file.file_key);
  if (!object) {
    return new Response(JSON.stringify({ error: 'File not found in storage' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  return new Response(object.body, {
    headers: {
      'Content-Type': file.content_type || 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${file.original_name}"`,
      ...corsHeaders
    }
  });
}

async function handleDeleteFile(request, env, corsHeaders) {
  const url = new URL(request.url);
  const parts = url.pathname.split('/');
  const id = parts[3];
  const fileKey = decodeURIComponent(parts[4]);

  if (id.startsWith('_')) {
    const payload = await requireAuthCookie(request, env);
    if (!payload) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  const file = await env.DB.prepare(
    'SELECT * FROM files WHERE unique_id = ? AND file_key = ?'
  ).bind(id, fileKey).first();

  if (!file) {
    return new Response(JSON.stringify({ error: 'File not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  await env.R2_BUCKET.delete(file.file_key);
  await env.DB.prepare(
    'DELETE FROM files WHERE unique_id = ? AND file_key = ?'
  ).bind(id, fileKey).run();

  return new Response(JSON.stringify({
    success: true,
    message: 'File deleted'
  }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleGetStats(request, env, corsHeaders) {
  const url = new URL(request.url);
  const id = url.pathname.split('/api/stats/')[1];

  if (id.startsWith('_')) {
    const payload = await requireAuthCookie(request, env);
    if (!payload) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  const limitCheck = await checkDailyUploadLimit(env.DB, id, 0, env);

  return new Response(JSON.stringify({
    quota: limitCheck,
    config: {
      maxFileSize: parseInt(env.MAX_FILE_SIZE),
      minExpiry: parseInt(env.MIN_EXPIRY_MINUTES),
      maxExpiry: parseInt(env.MAX_EXPIRY_MINUTES)
    }
  }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleR2Upload(request, env, corsHeaders) {
  const url = new URL(request.url);
  const fileKey = decodeURIComponent(url.pathname.split('/api/r2-upload/')[1]);
  const sessionToken = request.headers.get('X-Session-Token');

  if (!sessionToken) {
    return new Response(JSON.stringify({ error: 'Session token required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const session = await env.DB.prepare(
    'SELECT * FROM upload_sessions WHERE session_token = ? AND file_key = ? AND status = "pending"'
  ).bind(sessionToken, fileKey).first();

  if (!session) {
    return new Response(JSON.stringify({ error: 'Invalid session' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  if (session.unique_id.startsWith('_')) {
    const payload = await requireAuthCookie(request, env);
    if (!payload) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  try {
    await env.R2_BUCKET.put(fileKey, request.body, {
      httpMetadata: {
        contentType: 'application/octet-stream'
      }
    });

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    console.error('R2 upload error:', error);
    return new Response(JSON.stringify({ error: 'Upload failed' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// ------------- Quota + cleanup helpers -------------

async function checkDailyUploadLimit(db, id, newFileSize, env) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayTimestamp = today.getTime();
  const tomorrow = todayTimestamp + 86400000;

  const result = await db.prepare(`
    SELECT 
      COALESCE(SUM(size), 0) as total_size,
      COUNT(*) as file_count
    FROM files 
    WHERE unique_id = ? 
      AND uploaded_at >= ? 
      AND uploaded_at < ?
      AND status = 'completed'
  `).bind(id, todayTimestamp, tomorrow).first();

  const currentUsage = result?.total_size || 0;
  const fileCount = result?.file_count || 0;
  const dailyLimit = parseInt(env.DAILY_UPLOAD_LIMIT);
  const maxFiles = parseInt(env.MAX_FILES_PER_ID);

  const newTotalSize = currentUsage + newFileSize;
  const newFileCount = fileCount + 1;

  return {
    allowed: newTotalSize <= dailyLimit && newFileCount <= maxFiles,
    used: currentUsage,
    limit: dailyLimit,
    remaining: dailyLimit - currentUsage,
    fileCount,
    maxFiles,
    usagePercentage: dailyLimit > 0 
      ? Math.round((currentUsage / dailyLimit) * 100) 
      : 0
  };
}

async function cleanupExpiredFiles(env) {
  try {
    const now = Date.now();

    const expiredFiles = await env.DB.prepare(
      'SELECT file_key FROM files WHERE expire_at < ?'
    ).bind(now).all();

    for (const file of expiredFiles.results || []) {
      try {
        await env.R2_BUCKET.delete(file.file_key);
        await env.DB.prepare(
          'DELETE FROM files WHERE file_key = ?'
        ).bind(file.file_key).run();
      } catch (error) {
        console.error('Error deleting file:', error);
      }
    }

    await env.DB.prepare(
      'DELETE FROM upload_sessions WHERE expires_at < ? OR (created_at < ? AND upload_completed = 0)'
    ).bind(now, now - 3600000).run();

  } catch (error) {
    console.error('Cleanup error:', error);
  }
}