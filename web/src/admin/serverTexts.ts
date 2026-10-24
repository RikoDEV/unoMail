// Texts the server writes for the administrator (DNS and server health), in English with
// {{placeholders}}. The server sends each as a key and its values so that the interface can show
// it in the user's language. Listed here so that the translation test asks for every one; a
// server test (`every_text_is_listed_for_translation` in diagnostics.rs) keeps the list complete.

import { t } from '../i18n';

export const SERVER_TEXTS = [
  "{{host}} does not resolve.",
  "{{host}} points elsewhere; the policy is served by {{hostname}}.",
  "{{host}} points elsewhere; the settings are served by {{hostname}}.",
  "{{hostname}} does not resolve to an address.",
  "A valid certificate is installed.",
  "ClamAV is configured but does not answer; incoming mail is deferred until it returns.",
  "ClamAV is reachable; incoming mail is scanned for malware.",
  "Client autoconfiguration ({{service}})",
  "Could not resolve the probe host.",
  "DANE (TLSA)",
  "DANE is published for the current key. Keep the key when renewing the certificate, or update the record first.",
  "DKIM key ({{selector}})",
  "DKIM key",
  "DKIM public key is published.",
  "DKIM record is published with an empty key (revoked).",
  "DKIM record not found.",
  "DMARC is enforced, but aggregate reports are not sent to postmaster@{{domain}}.",
  "DMARC policy is enforced and aggregate reports are sent here.",
  "DMARC policy is p=none: failures are reported but not acted on.",
  "DMARC policy",
  "DMARC record has no valid policy (p=) tag.",
  "DNS lookup failed: {{error}}",
  "Incoming mail is not scanned for malware. Programs are refused by name, but infected documents get through; set UNOMAIL_CLAMAV_ADDR.",
  "Live DNS checks are unavailable.",
  "Mail programs find their settings here.",
  "Mail programs find this server.",
  "MTA-STS policy host",
  "MTA-STS record",
  "Multiple DMARC records found.",
  "Multiple SPF records found; receivers treat this as a permanent error.",
  "Multiple TLS reporting records found.",
  "MX points to this server.",
  "MX record",
  "MX records do not include {{hostname}}.",
  "No active DKIM key: outgoing mail for this domain is not signed.",
  "No ClamAV address is configured. Mail is scanned only if Rspamd's antivirus module is set up; set UNOMAIL_CLAMAV_ADDR to be sure.",
  "No DMARC record found.",
  "No MTA-STS record: senders do not know about the policy.",
  "No MX record found; other servers cannot deliver mail to this domain.",
  "No reverse DNS (PTR) record; many receivers reject mail from such addresses.",
  "No SPF record found.",
  "No TLS reporting record: you will not hear when other servers fail to reach yours securely.",
  "Optional: lets mail programs find this server on their own.",
  "Optional: lets mail programs set themselves up from the address alone.",
  "Optional: with DNSSEC on the zone, a TLSA record lets senders verify this server (DANE).",
  "Other servers report TLS problems to this domain's postmaster.",
  "Outbound connections on port 25 work.",
  "Outbound mail is sent through the configured default route.",
  "Outbound port 25 appears to be blocked; configure a relay host.",
  "Published DKIM key does not match the key used for signing.",
  "Reverse DNS (PTR)",
  "Reverse DNS does not match the server hostname {{hostname}}.",
  "Reverse DNS matches the server hostname.",
  "SPF for {{ip}} could not be evaluated because a DNS lookup failed.",
  "SPF record authorizes this server's IP addresses and rejects all others.",
  "SPF record does not authorize this server's IP address {{ip}}.",
  "SPF record does not end in -all, so other servers are not explicitly forbidden.",
  "SPF record ends in +all, which authorizes every server on the internet.",
  "SPF record is invalid or needs more than 10 DNS lookups, so receivers treat it as a permanent error.",
  "SPF record uses ?all (neutral); use ~all or -all.",
  "SPF record",
  "The {{mode}} policy is announced.",
  "The certificate does not cover {{host}}: add the name in Certificates, or senders cannot read the policy.",
  "The certificate expires in {{count}} days.",
  "The certificate is not valid for {{hostname}}.",
  "The policy is served by this server.",
  "The record does not point to port {{port}} on {{hostname}}.",
  "The record has another id: senders keep using the policy they saw before. Publish the new id.",
  "The server uses a self-signed certificate.",
  "The server's public IP address could not be determined, so this SPF record cannot be verified.",
  "The TLS reporting record does not send reports to postmaster@{{domain}}.",
  "The TLSA record does not match the current certificate: DANE senders will refuse to deliver.",
  "TLS certificate",
  "TLS reporting (TLS-RPT)",
];

/** A server text in the interface language; unknown texts (from a newer server) stay in English. */
export function serverText(key: string, params: Record<string, string> = {}, fallback = key): string {
  if (!SERVER_TEXTS.includes(key)) return fallback;
  // i18next picks plural forms from a number.
  const values: Record<string, unknown> = { ...params };
  if (params.count !== undefined) values.count = Number(params.count);
  return t(key, values);
}
