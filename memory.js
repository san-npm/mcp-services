// ─── Agent Memory Service ───
// Tools: memory_store, memory_get, memory_search, memory_list, memory_delete
// SQLite-based persistent storage, namespace-scoped per API key

import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';

const DB_PATH = process.env.MEMORY_DB_PATH || './data/memory.db';

// Ensure data dir exists
const dbDir = dirname(DB_PATH);
if (dbDir && dbDir !== '.' && !existsSync(dbDir)) {
  mkdirSync(dbDir, { recursive: true });
}

const db = new Database(DB_PATH);

// WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

// Create table
db.exec(`
  CREATE TABLE IF NOT EXISTS memories (
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    tags TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (namespace, key)
  )
`);

// Create FTS5 virtual table for full-text search
db.exec(`
  CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
    namespace,
    key,
    value,
    tags,
    content=memories,
    content_rowid=rowid
  )
`);

// Triggers to keep FTS in sync
db.exec(`
  CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
    INSERT INTO memories_fts(rowid, namespace, key, value, tags)
    VALUES (new.rowid, new.namespace, new.key, new.value, new.tags);
  END
`);

db.exec(`
  CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
    INSERT INTO memories_fts(memories_fts, rowid, namespace, key, value, tags)
    VALUES ('delete', old.rowid, old.namespace, old.key, old.value, old.tags);
  END
`);

db.exec(`
  CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
    INSERT INTO memories_fts(memories_fts, rowid, namespace, key, value, tags)
    VALUES ('delete', old.rowid, old.namespace, old.key, old.value, old.tags);
    INSERT INTO memories_fts(rowid, namespace, key, value, tags)
    VALUES (new.rowid, new.namespace, new.key, new.value, new.tags);
  END
`);

// ─── Namespace resolution ───
// API key users get their key hash as namespace prefix for isolation
// Free tier gets "free:<ip>" namespace
export function resolveNamespace(req, namespace) {
  const tier = req.authTier || 'free';
  if (tier === 'apikey') {
    const apiKey = req.headers['x-api-key'] || req.query.apikey || 'unknown';
    // Hash the key so we don't store raw keys in DB
    const hash = Buffer.from(apiKey).toString('base64url').slice(0, 16);
    return `key:${hash}:${namespace}`;
  }
  if (tier === 'x402') {
    // x402 users are anonymous but pay per call — use their payment receiver
    return `x402:${namespace}`;
  }
  // Free tier — scope by IP
  const ip = req.ip || 'unknown';
  return `free:${ip}:${namespace}`;
}

// ─── Prepared statements ───
const stmts = {
  upsert: db.prepare(`
    INSERT INTO memories (namespace, key, value, tags, created_at, updated_at)
    VALUES (@namespace, @key, @value, @tags, datetime('now'), datetime('now'))
    ON CONFLICT(namespace, key) DO UPDATE SET
      value = @value,
      tags = @tags,
      updated_at = datetime('now')
  `),

  get: db.prepare(`
    SELECT key, value, tags, created_at, updated_at
    FROM memories WHERE namespace = @namespace AND key = @key
  `),

  delete: db.prepare(`
    DELETE FROM memories WHERE namespace = @namespace AND key = @key
  `),

  list: db.prepare(`
    SELECT key, value, tags, created_at, updated_at
    FROM memories WHERE namespace = @namespace
    ORDER BY updated_at DESC
    LIMIT @limit OFFSET @offset
  `),

  count: db.prepare(`
    SELECT COUNT(*) as total FROM memories WHERE namespace = @namespace
  `),

  search: db.prepare(`
    SELECT m.key, m.value, m.tags, m.created_at, m.updated_at,
           rank
    FROM memories_fts f
    JOIN memories m ON m.rowid = f.rowid
    WHERE memories_fts MATCH @query AND f.namespace = @namespace
    ORDER BY rank
    LIMIT @limit
  `),

  // Fallback LIKE search when FTS query is invalid
  searchLike: db.prepare(`
    SELECT key, value, tags, created_at, updated_at
    FROM memories
    WHERE namespace = @namespace
      AND (key LIKE @pattern OR value LIKE @pattern OR tags LIKE @pattern)
    ORDER BY updated_at DESC
    LIMIT @limit
  `),
};

// ─── Handlers ───

export function memoryStore(namespace, key, value, tags = []) {
  if (!namespace || !key || !value) throw new Error('namespace, key, and value are required');
  if (key.length > 256) throw new Error('key must be 256 chars or less');
  if (value.length > 100000) throw new Error('value must be 100KB or less');
  if (namespace.length > 256) throw new Error('namespace must be 256 chars or less');

  const tagsJson = JSON.stringify(Array.isArray(tags) ? tags.slice(0, 20) : []);
  stmts.upsert.run({ namespace, key, value, tags: tagsJson });

  return { namespace, key, stored: true, tags: JSON.parse(tagsJson) };
}

export function memoryGet(namespace, key) {
  if (!namespace || !key) throw new Error('namespace and key are required');
  const row = stmts.get.get({ namespace, key });
  if (!row) return null;
  return {
    key: row.key,
    value: row.value,
    tags: JSON.parse(row.tags || '[]'),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function memorySearch(namespace, query, limit = 20) {
  if (!namespace || !query) throw new Error('namespace and query are required');
  const clampedLimit = Math.min(Math.max(limit, 1), 50);

  let rows;
  try {
    // Try FTS5 search first
    rows = stmts.search.all({ namespace, query, limit: clampedLimit });
  } catch {
    // Fallback to LIKE search if FTS query syntax is invalid
    const pattern = `%${query}%`;
    rows = stmts.searchLike.all({ namespace, pattern, limit: clampedLimit });
  }

  return {
    namespace,
    query,
    results: rows.map(r => ({
      key: r.key,
      value: r.value,
      tags: JSON.parse(r.tags || '[]'),
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    })),
    count: rows.length,
  };
}

export function memoryList(namespace, offset = 0, limit = 20) {
  if (!namespace) throw new Error('namespace is required');
  const clampedLimit = Math.min(Math.max(limit, 1), 100);
  const clampedOffset = Math.max(offset, 0);

  const { total } = stmts.count.get({ namespace });
  const rows = stmts.list.all({ namespace, limit: clampedLimit, offset: clampedOffset });

  return {
    namespace,
    items: rows.map(r => ({
      key: r.key,
      value: r.value.length > 200 ? r.value.slice(0, 200) + '...' : r.value,
      tags: JSON.parse(r.tags || '[]'),
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    })),
    total,
    offset: clampedOffset,
    limit: clampedLimit,
  };
}

export function memoryDelete(namespace, key) {
  if (!namespace || !key) throw new Error('namespace and key are required');
  const info = stmts.delete.run({ namespace, key });
  return { namespace, key, deleted: info.changes > 0 };
}
