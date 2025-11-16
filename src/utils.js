// Utility functions for file sharing

export function generateShortId() {
  const characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_';
  const length = 9;
  let result = '';
  
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  
  for (let i = 0; i < length; i++) {
    result += characters[randomValues[i] % characters.length];
  }
  
  return result;
}

export function generateSecureToken() {
  const buffer = new Uint8Array(32);
  crypto.getRandomValues(buffer);
  return Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function generateFileKey(uniqueId, originalName, sessionId) {
  const timestamp = Date.now();
  const randomBuffer = new Uint8Array(8);
  crypto.getRandomValues(randomBuffer);
  const randomString = Array.from(randomBuffer, b => b.toString(16).padStart(2, '0')).join('');
  
  const extension = originalName.includes('.') ? originalName.split('.').pop() : '';
  const hashInput = `${uniqueId}${sessionId}${timestamp}`;
  
  // Simple hash (in production, use Web Crypto API for SHA-256)
  let hash = 0;
  for (let i = 0; i < hashInput.length; i++) {
    hash = ((hash << 5) - hash) + hashInput.charCodeAt(i);
    hash = hash & hash;
  }
  const hashString = Math.abs(hash).toString(16).substring(0, 8);
  
  return `${uniqueId}/${hashString}_${timestamp}_${randomString}${extension ? '.' + extension : ''}`;
}

export function validateFileName(fileName) {
  const allowedExtensions = [
    'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'ico',
    'mp4', 'avi', 'mov', 'wmv', 'mkv', 'webm', 'm4v', 'flv',
    'mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'wma',
    'pdf', 'doc', 'docx', 'txt', 'rtf', 'odt', 'pages',
    'xls', 'xlsx', 'csv', 'ods', 'numbers',
    'ppt', 'pptx', 'odp', 'key',
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
    'js', 'html', 'css', 'json', 'xml', 'py', 'java', 'cpp', 'c', 'php', 'rb', 'go', 'rs', 'swift',
    'psd', 'ai', 'sketch', 'fig', 'epub', 'mobi'
  ];

  const dangerousPatterns = [
    /\.\./,
    /[<>:"|?*]/,
    /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i,
    /^\./,
    /\s+$/,
  ];

  if (dangerousPatterns.some(pattern => pattern.test(fileName))) {
    return false;
  }

  const extension = fileName.includes('.') 
    ? fileName.split('.').pop().toLowerCase() 
    : '';
    
  return allowedExtensions.includes(extension);
}

export function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function getFileIcon(fileName) {
  const extension = fileName.includes('.') 
    ? fileName.split('.').pop().toLowerCase() 
    : '';
    
  const iconMap = {
    'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'svg': '🖼️', 'webp': '🖼️',
    'mp4': '🎬', 'avi': '🎬', 'mov': '🎬', 'wmv': '🎬', 'mkv': '🎬', 'webm': '🎬',
    'mp3': '🎵', 'wav': '🎵', 'ogg': '🎵', 'flac': '🎵', 'aac': '🎵',
    'zip': '🗜️', 'rar': '🗜️', '7z': '🗜️', 'tar': '🗜️', 'gz': '🗜️',
    'pdf': '📄', 'doc': '📝', 'docx': '📝', 'txt': '📝', 'rtf': '📝',
    'xls': '📊', 'xlsx': '📊', 'csv': '📊',
    'ppt': '📊', 'pptx': '📊',
    'js': '💻', 'html': '💻', 'css': '💻', 'json': '💻', 'xml': '💻',
    'py': '🐍', 'java': '☕', 'cpp': '⚡', 'c': '⚡'
  };
  
  return iconMap[extension] || '📄';
}