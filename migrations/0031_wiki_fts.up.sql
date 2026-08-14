-- 0031: Wiki FTS5 search index (WU-503)
--
-- Standalone FTS5 table for wiki page content. Wiki pages live in git (not a
-- SQL base table), so unlike tasks_fts/comments_fts this is NOT content-sync;
-- the wiki indexer (internal/wiki) walks each org's checkout on refresh and
-- maintains the index. org_id + path are UNINDEXED (filter-only); title +
-- content are tokenized for MATCH. A page's visibility is org-scoped: a wiki
-- page belongs to its org, and any member of that org can read it (wiki.read).

CREATE VIRTUAL TABLE IF NOT EXISTS wiki_fts USING fts5(
    org_id UNINDEXED,
    path   UNINDEXED,
    name,
    content,
    tokenize='porter unicode61',
);
