-- Signatures: named, reusable pieces of HTML. Which one a sender address uses for new messages
-- and for replies/forwards is chosen per address (any identity, including the account's own
-- address before it was saved as an identity).
CREATE TABLE signatures (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    html       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (account_id, name)
) STRICT;

CREATE TABLE signature_defaults (
    account_id         INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email              TEXT NOT NULL,
    new_signature_id   INTEGER REFERENCES signatures(id) ON DELETE SET NULL,
    reply_signature_id INTEGER REFERENCES signatures(id) ON DELETE SET NULL,
    PRIMARY KEY (account_id, email)
) STRICT, WITHOUT ROWID;

-- Each identity's signature becomes a named signature (one per distinct text, named after the
-- first address using it), used for both new messages and replies.
INSERT INTO signatures (account_id, name, html, created_at)
SELECT account_id, min(email), signature_html, unixepoch() FROM identities WHERE signature_html <> '' GROUP BY account_id, signature_html;

INSERT INTO signature_defaults (account_id, email, new_signature_id, reply_signature_id)
SELECT i.account_id, i.email, s.id, s.id FROM identities i JOIN signatures s ON s.account_id = i.account_id AND s.html = i.signature_html WHERE i.signature_html <> '';

ALTER TABLE identities DROP COLUMN signature_html;
