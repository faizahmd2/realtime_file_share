import { generateShortId, generateSecureToken, generateFileKey, validateFileName } from './utils';
import dashboardHTML from './dashboard.html';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Session-Token',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Root and dashboard
      if (path === '/' || path === '/dashboard') {
        const uniqueId = url.searchParams.get('uniqueId');
        if (!uniqueId) {
          const newId = generateShortId();
          return Response.redirect(`${url.origin}/dashboard?uniqueId=${newId}`, 302);
        }
        return new Response(dashboardHTML, {
          headers: { 'Content-Type': 'text/html', ...corsHeaders }
        });
      }

      // Health check
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

      // Initialize upload session
      if (path === '/api/init-upload' && request.method === 'POST') {
        return await handleInitUpload(request, env, corsHeaders);
      }

      // Get upload credentials
      if (path === '/api/upload-credentials' && request.method === 'POST') {
        return await handleUploadCredentials(request, env, corsHeaders);
      }

      // Complete upload
      if (path === '/api/upload-complete' && request.method === 'POST') {
        return await handleUploadComplete(request, env, corsHeaders);
      }

      // List files
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

      // Get stats
      if (path.startsWith('/api/stats/') && request.method === 'GET') {
        return await handleGetStats(request, env, corsHeaders);
      }

      // Direct R2 upload
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

// Handler functions
async function handleInitUpload(request, env, corsHeaders) {
  const body = await request.json();
  const { uniqueId, fileName, fileSize, expiryMinutes, clientFingerprint } = body;

  if (!uniqueId || !fileName || !fileSize || !expiryMinutes || !clientFingerprint) {
    return new Response(JSON.stringify({ error: 'Missing required fields' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
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

  // Check daily limits
  const limitCheck = await checkDailyUploadLimit(env.DB, uniqueId, fileSize, env);
  if (!limitCheck.allowed) {
    return new Response(JSON.stringify({ 
      error: 'Daily upload limit exceeded',
      quota: limitCheck
    }), {
      status: 429,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // Create session
  const sessionToken = generateSecureToken();
  const sessionId = crypto.randomUUID();
  const fileKey = generateFileKey(uniqueId, fileName, sessionId);
  const now = Date.now();

  await env.DB.prepare(`
    INSERT INTO upload_sessions 
    (session_id, session_token, unique_id, file_key, file_name, file_size, 
     expiry_minutes, client_fingerprint, status, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
  `).bind(
    sessionId, sessionToken, uniqueId, fileKey, fileName, fileSize,
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

  if (session.upload_started) {
    return new Response(JSON.stringify({ error: 'Upload already started' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const body = await request.json();
  const contentType = body.contentType || 'application/octet-stream';

  // Generate R2 presigned URL
  const uploadUrl = await env.R2_BUCKET.createMultipartUpload(session.file_key, {
    httpMetadata: { contentType }
  });

  // Mark session as started
  await env.DB.prepare(
    'UPDATE upload_sessions SET upload_started = 1 WHERE session_id = ?'
  ).bind(session.session_id).run();

  // For simple uploads, generate a PUT URL
  const expirationTime = Math.floor(Date.now() / 1000) + 1800; // 30 minutes
  
  return new Response(JSON.stringify({
    uploadUrl: `${url.origin}/api/r2-upload/${session.file_key}`,
    fileKey: session.file_key,
    sessionToken: sessionToken
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

//   if (!session.upload_started) {
//     return new Response(JSON.stringify({ error: 'Upload not started' }), {
//       status: 400,
//       headers: { 'Content-Type': 'application/json', ...corsHeaders }
//     });
//   }

  const now = Date.now();
  const expireAt = now + (session.expiry_minutes * 60 * 1000);

  // Store file metadata
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

  // Mark session as completed
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
  const uniqueId = url.searchParams.get('uniqueId');

  if (!uniqueId) {
    return new Response(JSON.stringify({ error: 'uniqueId required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const now = Date.now();
  const files = await env.DB.prepare(
    'SELECT id, unique_id, file_key, original_name, size, expire_at, uploaded_at FROM files WHERE unique_id = ? AND expire_at > ? AND status = "completed" ORDER BY uploaded_at DESC'
  ).bind(uniqueId, now).all();

  const limitCheck = await checkDailyUploadLimit(env.DB, uniqueId, 0, env);

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
  const uniqueId = parts[3];
  const fileKey = decodeURIComponent(parts[4]);

  const file = await env.DB.prepare(
    'SELECT * FROM files WHERE unique_id = ? AND file_key = ? AND expire_at > ? AND status = "completed"'
  ).bind(uniqueId, fileKey, Date.now()).first();

  if (!file) {
    return new Response(JSON.stringify({ error: 'File not found or expired' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // Get file from R2
  const object = await env.R2_BUCKET.get(file.file_key);
  
  if (!object) {
    return new Response(JSON.stringify({ error: 'File not found in storage' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // Return file directly
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
  const uniqueId = parts[3];
  const fileKey = decodeURIComponent(parts[4]);

  const file = await env.DB.prepare(
    'SELECT * FROM files WHERE unique_id = ? AND file_key = ?'
  ).bind(uniqueId, fileKey).first();

  if (!file) {
    return new Response(JSON.stringify({ error: 'File not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // Delete from R2
  await env.R2_BUCKET.delete(file.file_key);

  // Delete from database
  await env.DB.prepare(
    'DELETE FROM files WHERE unique_id = ? AND file_key = ?'
  ).bind(uniqueId, fileKey).run();

  return new Response(JSON.stringify({ 
    success: true, 
    message: 'File deleted' 
  }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleGetStats(request, env, corsHeaders) {
  const url = new URL(request.url);
  const uniqueId = url.pathname.split('/api/stats/')[1];

  const limitCheck = await checkDailyUploadLimit(env.DB, uniqueId, 0, env);

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

  // Validate session
  const session = await env.DB.prepare(
    'SELECT * FROM upload_sessions WHERE session_token = ? AND file_key = ? AND status = "pending"'
  ).bind(sessionToken, fileKey).first();

  if (!session) {
    return new Response(JSON.stringify({ error: 'Invalid session' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  try {
    // Upload directly to R2
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

// Helper functions
async function checkDailyUploadLimit(db, uniqueId, newFileSize, env) {
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
  `).bind(uniqueId, todayTimestamp, tomorrow).first();

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
    fileCount: fileCount,
    maxFiles: maxFiles,
    usagePercentage: Math.round((currentUsage / dailyLimit) * 100)
  };
}

async function cleanupExpiredFiles(env) {
  try {
    const now = Date.now();
    
    // Get expired files
    const expiredFiles = await env.DB.prepare(
      'SELECT file_key FROM files WHERE expire_at < ?'
    ).bind(now).all();

    // Delete from R2 and database
    for (const file of expiredFiles.results || []) {
      try {
        await env.R2_BUCKET.delete(file.file_key);
        await env.DB.prepare('DELETE FROM files WHERE file_key = ?').bind(file.file_key).run();
      } catch (error) {
        console.error('Error deleting file:', error);
      }
    }

    // Cleanup old sessions
    await env.DB.prepare(
      'DELETE FROM upload_sessions WHERE expires_at < ? OR (created_at < ? AND upload_completed = 0)'
    ).bind(now, now - 3600000).run();

    console.log(`Cleanup completed: ${expiredFiles.results?.length || 0} files removed`);
  } catch (error) {
    console.error('Cleanup error:', error);
  }
}