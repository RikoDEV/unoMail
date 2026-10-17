//! OpenAPI 3.1 description of the management API, served at `/api/openapi.json`.

use axum::Json;
use serde_json::{Map, Value, json};

/// (method, path, tag, summary, required role)
const OPERATIONS: &[(&str, &str, &str, &str, &str)] = &[
    ("post", "/api/auth/login", "auth", "Sign in and start a session", "public"),
    ("post", "/api/auth/logout", "auth", "End the current session", "user"),
    ("get", "/api/auth/me", "auth", "Current account and CSRF token", "user"),
    ("get", "/api/auth/accounts", "auth", "Every account this browser is signed in to", "user"),
    ("post", "/api/auth/switch", "auth", "Make another signed-in account the current one", "user"),
    ("post", "/api/auth/password", "auth", "Change the password of the current account", "user"),
    ("post", "/api/auth/second-factor", "auth", "Second step of a sign-in: authenticator code, passkey or recovery code", "public"),
    ("post", "/api/auth/second-factor/passkey", "auth", "A new passkey challenge for a waiting sign-in", "public"),
    ("get", "/api/auth/passkey", "auth", "Options for signing in with a passkey alone (no address or password)", "public"),
    ("post", "/api/auth/passkey", "auth", "Sign in with a passkey", "public"),
    ("get", "/api/me/two-factor", "auth", "Second sign-in factors of the account", "user"),
    ("get", "/api/tls-reports", "reports", "TLS reports received about hosted domains, and outgoing TLS results", "domain_admin"),
    ("post", "/api/me/two-factor/totp", "auth", "Start setting up an authenticator app", "user"),
    ("put", "/api/me/two-factor/totp", "auth", "Turn the authenticator app on with a code from it", "user"),
    ("delete", "/api/me/two-factor/totp", "auth", "Turn the authenticator app off (password required)", "user"),
    ("post", "/api/me/two-factor/recovery-codes", "auth", "New recovery codes (password required)", "user"),
    ("post", "/api/me/passkeys/register/options", "auth", "Options for registering a passkey (requires the password)", "user"),
    ("post", "/api/me/passkeys/register", "auth", "Register a passkey", "user"),
    ("delete", "/api/me/passkeys/{id}", "auth", "Remove a passkey (password required)", "user"),
    ("patch", "/api/me/passkeys/{id}", "auth", "Rename a passkey", "user"),
    ("get", "/api/me/app-passwords", "auth", "App passwords of the account", "user"),
    ("post", "/api/me/app-passwords", "auth", "Create an app password (password required)", "user"),
    ("delete", "/api/me/app-passwords/{id}", "auth", "Revoke an app password", "user"),
    ("get", "/api/me/pgp/encryption", "auth", "Whether incoming mail is stored encrypted to the account's OpenPGP key", "user"),
    ("put", "/api/me/pgp/encryption", "auth", "Start or stop storing incoming mail encrypted", "user"),
    ("get", "/api/me/smime", "auth", "The account's S/MIME certificate and correspondents' certificates", "user"),
    ("put", "/api/me/smime", "auth", "Import an S/MIME certificate and key (PKCS #12, base64)", "user"),
    ("delete", "/api/me/smime", "auth", "Remove the S/MIME certificate", "user"),
    ("get", "/api/me/smime/lookup", "auth", "Which addresses mail can be encrypted to with S/MIME", "user"),
    ("get", "/api/me/snoozes", "mail", "Snoozed messages and when they return", "user"),
    ("post", "/api/me/snoozes", "mail", "Snooze messages until a time", "user"),
    ("delete", "/api/me/snoozes/{id}", "mail", "Bring a snoozed message back now", "user"),
    ("get", "/api/lists", "lists", "Mailing lists", "domain_admin"),
    ("post", "/api/lists", "lists", "Create a mailing list", "domain_admin"),
    ("get", "/api/lists/{id}", "lists", "Get a mailing list", "domain_admin"),
    ("patch", "/api/lists/{id}", "lists", "Change a mailing list", "domain_admin"),
    ("delete", "/api/lists/{id}", "lists", "Delete a mailing list", "domain_admin"),
    ("get", "/api/lists/{id}/members", "lists", "Members of a list", "domain_admin"),
    ("post", "/api/lists/{id}/members", "lists", "Add members (one address per line)", "domain_admin"),
    ("patch", "/api/lists/{id}/members/{member}", "lists", "Change a member's role", "domain_admin"),
    ("delete", "/api/lists/{id}/members/{member}", "lists", "Remove a member", "domain_admin"),
    ("get", "/api/lists/{id}/held", "lists", "Posts waiting for a moderator", "domain_admin"),
    ("post", "/api/lists/{id}/held/{token}", "lists", "Approve or discard a held post", "domain_admin"),
    ("get", "/api/backups", "system", "Backup target, snapshots and recent runs", "super_admin"),
    ("post", "/api/backups", "system", "Start a backup now", "super_admin"),
    ("get", "/api/accounts/{id}/two-factor", "mailboxes", "Whether a mailbox uses two-step sign-in", "domain_admin"),
    ("delete", "/api/accounts/{id}/two-factor", "mailboxes", "Reset the second factors of a mailbox", "domain_admin"),
    ("get", "/api/auth/sessions", "auth", "List active sessions", "user"),
    ("delete", "/api/auth/sessions", "auth", "Sign out all other sessions", "user"),
    ("get", "/api/domains", "domains", "List domains", "domain_admin"),
    ("post", "/api/domains", "domains", "Create a domain (generates a DKIM key)", "super_admin"),
    ("get", "/api/domains/{id}", "domains", "Get a domain", "domain_admin"),
    ("patch", "/api/domains/{id}", "domains", "Update a domain", "domain_admin"),
    ("delete", "/api/domains/{id}", "domains", "Delete a domain with all its mailboxes", "super_admin"),
    ("get", "/api/domains/{id}/dns", "domains", "Required DNS records with live MX/SPF/DKIM/DMARC/PTR/TLS checks", "domain_admin"),
    ("get", "/api/domains/{id}/dkim", "dkim", "List DKIM keys", "domain_admin"),
    ("post", "/api/domains/{id}/dkim", "dkim", "Generate a DKIM key for a new selector", "domain_admin"),
    ("patch", "/api/domains/{id}/dkim/{key_id}", "dkim", "Activate or deactivate a DKIM key", "domain_admin"),
    ("delete", "/api/domains/{id}/dkim/{key_id}", "dkim", "Delete a DKIM key", "domain_admin"),
    ("get", "/api/domains/{id}/admins", "domains", "List delegated administrators", "super_admin"),
    ("put", "/api/domains/{id}/admins", "domains", "Replace delegated administrators", "super_admin"),
    ("get", "/api/accounts", "mailboxes", "List mailboxes", "domain_admin"),
    ("post", "/api/accounts", "mailboxes", "Create a mailbox", "domain_admin"),
    ("get", "/api/accounts/{id}", "mailboxes", "Get a mailbox", "domain_admin"),
    ("patch", "/api/accounts/{id}", "mailboxes", "Update quota, password, protocol access or sending block", "domain_admin"),
    ("delete", "/api/accounts/{id}", "mailboxes", "Delete a mailbox and its mail", "domain_admin"),
    ("get", "/api/aliases", "aliases", "List aliases", "domain_admin"),
    ("post", "/api/aliases", "aliases", "Create an alias or redirect", "domain_admin"),
    ("patch", "/api/aliases/{id}", "aliases", "Update an alias", "domain_admin"),
    ("delete", "/api/aliases/{id}", "aliases", "Delete an alias", "domain_admin"),
    ("get", "/api/tls", "certificates", "Active certificate and automation status", "super_admin"),
    ("post", "/api/tls/validate", "certificates", "Validate a certificate and key without installing them", "super_admin"),
    ("put", "/api/tls/custom", "certificates", "Install a custom certificate (hot reload)", "super_admin"),
    ("post", "/api/tls/self-signed", "certificates", "Revert to a self-signed certificate", "super_admin"),
    ("put", "/api/tls/acme", "certificates", "Configure Let's Encrypt and request a certificate", "super_admin"),
    ("delete", "/api/tls/acme", "certificates", "Disable automatic certificates", "super_admin"),
    ("post", "/api/tls/acme/renew", "certificates", "Renew the automatic certificate now", "super_admin"),
    ("get", "/api/dashboard", "system", "Server overview metrics", "super_admin"),
    ("get", "/api/diagnostics/server", "system", "Port, blocklist and deliverability checks", "super_admin"),
    ("get", "/api/queue", "queue", "List the outbound delivery queue", "super_admin"),
    ("post", "/api/queue/{id}/retry", "queue", "Retry a queued message now", "super_admin"),
    ("delete", "/api/queue/{id}", "queue", "Remove a message from the queue", "super_admin"),
    ("get", "/api/logs/delivery", "logs", "Delivery log (supports q, status, after, before, limit)", "domain_admin"),
    ("get", "/api/logs/audit", "logs", "Security audit log", "super_admin"),
    ("get", "/api/logs/system", "logs", "Recent system log lines", "super_admin"),
    ("get", "/api/logs/stream", "logs", "Live log stream (server-sent events; kind=delivery|audit|system)", "domain_admin"),
    ("get", "/api/settings", "system", "Runtime server settings with defaults", "super_admin"),
    ("patch", "/api/settings", "system", "Change runtime server settings (null resets to the default)", "super_admin"),
    ("get", "/api/dmarc", "dmarc", "DMARC aggregate report summary, sources and reports", "domain_admin"),
    ("post", "/api/dmarc/reports", "dmarc", "Upload an aggregate report (XML, gzip, zip or e-mail)", "super_admin"),
    ("get", "/api/dmarc/reports/{id}", "dmarc", "Records of one aggregate report", "domain_admin"),
    ("get", "/api/accounts/{id}/import", "mailboxes", "Import jobs of a mailbox", "domain_admin"),
    ("post", "/api/accounts/{id}/import", "mailboxes", "Start an IMAP or Maildir import", "domain_admin"),
    ("get", "/api/me/sieve", "user", "Sieve filter script", "user"),
    ("put", "/api/me/sieve", "user", "Validate and save the Sieve filter script", "user"),
    ("get", "/api/me/sieve/scripts", "user", "Names of stored filter scripts", "user"),
    ("get", "/api/sieve/global", "system", "Global filter scripts for include :global", "super_admin"),
    ("put", "/api/sieve/global", "system", "Validate and store a global filter script", "super_admin"),
    ("delete", "/api/sieve/global", "system", "Delete a global filter script (?name=)", "super_admin"),
    ("delete", "/api/me/sieve", "user", "Delete a filter script (?name=)", "user"),
    ("get", "/api/me/labels", "user", "Labels (keywords) in use", "user"),
    ("delete", "/api/me/labels", "user", "Remove a label from every message (?name=)", "user"),
    ("post", "/api/me/labels/rename", "user", "Rename a label", "user"),
    ("get", "/api/me/vacation", "user", "Out-of-office settings", "user"),
    ("put", "/api/me/vacation", "user", "Update out-of-office settings", "user"),
    ("get", "/health", "monitoring", "Liveness probe", "public"),
    ("get", "/metrics", "monitoring", "Prometheus metrics (private networks or bearer token)", "public"),
    ("get", "/.well-known/jmap", "jmap", "JMAP session resource (RFC 8620)", "user"),
    ("post", "/jmap/api", "jmap", "JMAP method calls: Mailbox, Email, Thread, Identity, EmailSubmission", "user"),
    ("post", "/jmap/upload/{accountId}", "jmap", "Upload a blob", "user"),
    ("get", "/jmap/download/{accountId}/{blobId}/{name}", "jmap", "Download a blob", "user"),
    ("get", "/jmap/eventsource", "jmap", "Push channel announcing state changes", "user"),
    ("get", "/api/auth/oauth", "auth", "Whether single sign-on is offered", "public"),
    ("get", "/api/auth/oauth/start", "auth", "Start single sign-on (redirects to the identity provider)", "public"),
    ("get", "/api/auth/oauth/callback", "auth", "Complete single sign-on", "public"),
    ("get", "/api/auth/oauth/result", "auth", "Outcome of the last single sign-on attempt (error or second step)", "public"),
    ("get", "/api/oauth", "integrations", "Single sign-on configuration", "super_admin"),
    ("put", "/api/oauth", "integrations", "Configure single sign-on (OpenID Connect)", "super_admin"),
    ("get", "/api/me/identities", "webmail", "List sender identities", "user"),
    ("post", "/api/me/identities", "webmail", "Create a sender identity, optionally with its own SMTP server", "user"),
    ("put", "/api/me/identities/{id}", "webmail", "Update a sender identity", "user"),
    ("delete", "/api/me/identities/{id}", "webmail", "Delete a sender identity", "user"),
    ("get", "/api/me/contacts", "address book", "List or search contacts", "user"),
    ("post", "/api/me/contacts", "address book", "Create a contact", "user"),
    ("put", "/api/me/contacts/{id}", "address book", "Update a contact", "user"),
    ("delete", "/api/me/contacts/{id}", "address book", "Delete a contact", "user"),
    ("get", "/api/me/contacts/suggest", "address book", "Recipient suggestions from contacts, groups, the domain directory and LDAP", "user"),
    ("get", "/api/me/contacts/export", "address book", "Export the address book as vCards", "user"),
    ("post", "/api/me/contacts/import", "address book", "Import vCards", "user"),
    ("get", "/api/me/contact-groups", "address book", "List contact groups", "user"),
    ("post", "/api/me/contact-groups", "address book", "Create a contact group", "user"),
    ("put", "/api/me/contact-groups/{id}", "address book", "Rename a contact group", "user"),
    ("delete", "/api/me/contact-groups/{id}", "address book", "Delete a contact group", "user"),
    ("get", "/api/me/contact-groups/{id}/members", "address book", "Members of a contact group", "user"),
    ("put", "/api/me/contact-groups/{id}/members", "address book", "Replace the members of a contact group", "user"),
    ("get", "/api/me/signatures", "webmail", "Signatures, and which one each sender identity uses for new messages and replies", "user"),
    ("post", "/api/me/signatures", "webmail", "Create a signature", "user"),
    ("put", "/api/me/signatures/defaults", "webmail", "Choose the signatures a sender identity uses", "user"),
    ("put", "/api/me/signatures/{id}", "webmail", "Change a signature", "user"),
    ("delete", "/api/me/signatures/{id}", "webmail", "Delete a signature", "user"),
    ("get", "/api/me/templates", "webmail", "List response templates", "user"),
    ("post", "/api/me/templates", "webmail", "Create a response template", "user"),
    ("put", "/api/me/templates/{id}", "webmail", "Update a response template", "user"),
    ("delete", "/api/me/templates/{id}", "webmail", "Delete a response template", "user"),
    ("get", "/api/me/preferences", "webmail", "Web client preferences", "user"),
    ("put", "/api/me/preferences", "webmail", "Store web client preferences", "user"),
    ("get", "/api/me/pgp", "webmail", "The account's OpenPGP keys", "user"),
    ("put", "/api/me/pgp", "webmail", "Store the public key and the passphrase-protected private key", "user"),
    ("delete", "/api/me/pgp", "webmail", "Remove the stored OpenPGP keys", "user"),
    ("get", "/api/me/pgp/lookup", "webmail", "Public keys of recipients", "user"),
    ("get", "/api/me/mailboxes/{id}/export", "folders", "Download a folder as an mbox file", "user"),
    ("post", "/api/me/mailboxes/{id}/import", "folders", "Import an .eml file or mbox archive into a folder", "user"),
    ("get", "/api/me/mailboxes/{id}/acl", "folders", "Who a folder is shared with", "user"),
    ("put", "/api/me/mailboxes/{id}/acl", "folders", "Share a folder with a user or with everyone in the domain", "user"),
    ("get", "/api/me/image-proxy", "webmail", "Fetch a remote image on the reader's behalf", "user"),
    ("get", "/api/ldap", "integrations", "LDAP directory configuration", "super_admin"),
    ("put", "/api/ldap", "integrations", "Configure the LDAP directory", "super_admin"),
    ("post", "/api/ldap/test", "integrations", "Try a directory search with unsaved settings", "super_admin"),
    ("get", "/api/skins", "integrations", "Installed skins", "user"),
    ("put", "/api/skins", "integrations", "Replace the installed skins", "super_admin"),
    ("get", "/api/plugins", "integrations", "Installed web client plug-ins", "user"),
    ("put", "/api/plugins/{id}", "integrations", "Enable or disable a plug-in", "super_admin"),
    ("get", "/api/webhooks", "integrations", "List webhooks", "super_admin"),
    ("post", "/api/webhooks", "integrations", "Create a webhook (returns the signing secret once)", "super_admin"),
    ("put", "/api/webhooks/{id}", "integrations", "Update a webhook", "super_admin"),
    ("delete", "/api/webhooks/{id}", "integrations", "Delete a webhook", "super_admin"),
    ("post", "/api/webhooks/{id}/test", "integrations", "Send a test event to a webhook", "super_admin"),
    ("get", "/api/dashboard/activity", "system", "Recently connected remote addresses and the latest SMTP replies", "super_admin"),
    ("get", "/api/dashboard/system", "system", "Free disk space and memory use over time", "super_admin"),
    ("get", "/api/dashboard/daily", "system", "SMTP connections and delivered, bounced, quarantined and discarded mail per day (?days=)", "super_admin"),
    ("get", "/api/smtp-access/rules", "smtp access", "Blacklist and whitelist rules (source=user or auto)", "super_admin"),
    ("post", "/api/smtp-access/rules", "smtp access", "Add an address or network to the blacklist or whitelist", "super_admin"),
    ("put", "/api/smtp-access/rules/{id}", "smtp access", "Change a rule (an automatic rule becomes a permanent one)", "super_admin"),
    ("delete", "/api/smtp-access/rules/{id}", "smtp access", "Delete a rule", "super_admin"),
    ("get", "/api/smtp-access/karma", "smtp access", "Behaviour scores of remote addresses", "super_admin"),
    ("delete", "/api/smtp-access/karma/{ip}", "smtp access", "Forget the score of an address", "super_admin"),
    ("get", "/api/spam-filter", "spam filter", "Rspamd status, thresholds, rule scores and recent verdicts", "super_admin"),
    ("put", "/api/spam-filter/thresholds", "spam filter", "Set the scores at which mail is marked as spam or rejected", "super_admin"),
    ("put", "/api/spam-filter/rules", "spam filter", "Change the score of one Rspamd rule", "super_admin"),
    ("get", "/api/me/startup", "webmail", "Preferences, skins and enabled plug-ins in one answer, for the web client's start", "user"),
    ("get", "/api/me/spam-filter", "webmail", "What the personal spam filter has learned from the user's reports", "user"),
    ("delete", "/api/me/spam-filter", "webmail", "Forget what the personal spam filter has learned", "user"),
    ("get", "/api/me/blocked-senders", "webmail", "Senders whose mail goes straight to Junk", "user"),
    ("post", "/api/me/blocked-senders", "webmail", "Block an address or a whole domain (@domain)", "user"),
    ("delete", "/api/me/blocked-senders", "webmail", "Unblock a sender", "user"),
    ("get", "/api/me/label-details", "webmail", "Labels with their colours", "user"),
    ("put", "/api/me/label-details", "webmail", "Define a label or change its colour", "user"),
    ("get", "/api/me/categories", "webmail", "Unread conversations per inbox category", "user"),
    ("get", "/api/me/categories/learning", "webmail", "What the inbox categories have learned from the user's corrections", "user"),
    ("delete", "/api/me/categories/learning", "webmail", "Forget what the inbox categories have learned", "user"),
    ("get", "/api/me/calendars", "calendar", "Calendars of the account and the CalDAV addresses", "user"),
    ("post", "/api/me/calendars", "calendar", "Create a calendar", "user"),
    ("patch", "/api/me/calendars/{id}", "calendar", "Rename or recolour a calendar", "user"),
    ("delete", "/api/me/calendars/{id}", "calendar", "Delete a calendar with its events", "user"),
    ("get", "/api/me/calendars/events", "calendar", "Occurrences of all events in a time window (recurrences expanded)", "user"),
    ("post", "/api/me/calendars/{id}/events", "calendar", "Create an event", "user"),
    ("get", "/api/me/calendars/{id}/events/{object_id}", "calendar", "Get an event for editing", "user"),
    ("put", "/api/me/calendars/{id}/events/{object_id}", "calendar", "Change an event, optionally moving it to another calendar", "user"),
    ("delete", "/api/me/calendars/{id}/events/{object_id}", "calendar", "Delete an event or one occurrence of a recurring event", "user"),
    ("get", "/api/me/calendars/{id}/shares", "calendar", "With whom a calendar is shared", "user"),
    ("put", "/api/me/calendars/{id}/shares", "calendar", "Share a calendar with colleagues of the same domain", "user"),
    ("get", "/api/me/calendars/tasks", "calendar", "List to-dos", "user"),
    ("post", "/api/me/calendars/{id}/tasks", "calendar", "Create a to-do", "user"),
    ("put", "/api/me/calendars/{id}/tasks/{object_id}", "calendar", "Change or complete a to-do", "user"),
    ("get", "/api/me/calendars/reminders", "calendar", "Reminders falling due in a time window", "user"),
    ("get", "/api/me/calendars/freebusy", "calendar", "Busy times of colleagues of the same domain", "user"),
    ("post", "/api/me/calendars/invitations/inspect", "calendar", "Describe an invitation received by mail", "user"),
    ("post", "/api/me/calendars/invitations/respond", "calendar", "Accept or decline an invitation and tell the organizer", "user"),
    ("get", "/api/me/calendars/{id}/export", "calendar", "Download a calendar as an iCalendar file", "user"),
    ("post", "/api/me/calendars/{id}/import", "calendar", "Import an iCalendar file", "user"),
    ("post", "/api/me/unsubscribe", "webmail", "Unsubscribe from the mailing list a message came from", "user"),
];

pub fn document(hostname: &str) -> Value {
    let mut paths = Map::new();
    for (method, path, tag, summary, role) in OPERATIONS {
        let parameters: Vec<Value> = path
            .split('/')
            .filter_map(|segment| segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
            .map(|name| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string" } }))
            .collect();
        let mut operation = json!({
            "tags": [tag],
            "summary": summary,
            "description": format!("Required role: {role}."),
            "parameters": parameters,
            "responses": {
                "200": { "description": "Success" },
                "400": { "$ref": "#/components/responses/Error" },
                "401": { "$ref": "#/components/responses/Error" },
                "403": { "$ref": "#/components/responses/Error" },
            },
        });
        if *role != "public" {
            let mut security = vec![json!({ "session": [] })];
            if *method != "get" {
                security = vec![json!({ "session": [], "csrf": [] })];
            }
            operation["security"] = json!(security);
        }
        if matches!(*method, "post" | "put" | "patch") {
            operation["requestBody"] = json!({ "content": { "application/json": { "schema": { "type": "object" } } } });
        }
        paths.entry(path.to_string()).or_insert_with(|| json!({})).as_object_mut().expect("path item is an object").insert(method.to_string(), operation);
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "unoMail API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Management API of the unoMail server. Sign in with POST /api/auth/login; the session is an HttpOnly cookie and every state-changing request must carry the CSRF token returned at login in the X-CSRF-Token header. Mail access uses JMAP.",
        },
        "servers": [{ "url": format!("https://{hostname}") }],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "session": { "type": "apiKey", "in": "cookie", "name": "__Host-unomail" },
                "csrf": { "type": "apiKey", "in": "header", "name": "X-CSRF-Token" },
            },
            "responses": {
                "Error": {
                    "description": "Error",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } },
                },
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "object",
                            "properties": { "code": { "type": "string" }, "message": { "type": "string" } },
                            "required": ["code", "message"],
                        },
                    },
                    "required": ["error"],
                },
            },
        },
    })
}

pub async fn serve(axum::extract::State(state): axum::extract::State<crate::app::AppState>) -> Json<Value> {
    Json(document(&state.cfg.hostname))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_is_well_formed() {
        let doc = document("mail.example.com");
        assert_eq!(doc["openapi"], "3.1.0");
        let paths = doc["paths"].as_object().unwrap();
        assert!(paths.len() > 30);
        assert!(paths["/api/domains/{id}"]["patch"]["parameters"][0]["name"] == "id");
        assert!(paths["/api/auth/login"]["post"].get("security").is_none());
        assert_eq!(paths["/api/domains"]["post"]["security"][0], json!({ "session": [], "csrf": [] }));
        assert_eq!(paths["/api/domains"]["get"]["security"][0], json!({ "session": [] }));
        // No duplicate (method, path) pairs in the table.
        let mut seen = std::collections::HashSet::new();
        assert!(OPERATIONS.iter().all(|(m, p, ..)| seen.insert((m, p))));
    }
}
