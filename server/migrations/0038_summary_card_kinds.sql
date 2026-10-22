-- Summary cards beyond purchases: reservations (travel, dining, events) and bills share the
-- card and source tables; `kind` says how a source's `details` JSON is read.
ALTER TABLE purchase_cards ADD COLUMN kind TEXT NOT NULL DEFAULT 'purchase';
