# Deployment and upgrades

See the [quick start](../README.md#quick-start) to run the container.

## Requirements

| Requirement | Notes |
| --- | --- |
| Outbound port 25 | Often blocked by providers. Otherwise set a relay in **Server settings**. |
| Static IP with PTR | The reverse DNS must name `UNOMAIL_HOSTNAME`. Set it at your hosting provider. |
| Inbound ports | 25, 80, 143, 443, 465, 587, 993, 995 (4190 for ManageSieve) |
| Memory | Over 1 GB for ClamAV, or set `CLAMAV_ENABLED=false` |
| DNS resolver | Your own, if you use Spamhaus |

## DNS

Create an A (and AAAA) record for `UNOMAIL_HOSTNAME`. For each domain,
**Administration → Domains** shows the records to publish and checks them:

| Record | Purpose |
| --- | --- |
| MX | Routes mail to the server |
| SPF | Authorizes the server to send |
| DKIM | Signing key |
| DMARC | Policy and reports. Start with `p=none`. |
| MTA-STS, TLS-RPT | Optional TLS enforcement and reports |

## Upgrading

Images: `ghcr.io/rikodev/unomail` with tags `X.Y.Z`, `X.Y` and `latest`.

1. Read the [release notes](https://github.com/RikoDEV/unoMail/releases).
2. Back up: `docker compose exec -u unomail unomail unomail backup`. Keep copies of
   `secret.key`, `blob.key` and `vapid.key`.
3. Update: `docker compose pull && docker compose up -d`

Migrations run at startup.

> [!WARNING]
> Migrations are forward-only. To downgrade, restore the backup taken before the upgrade.

## Troubleshooting

Check the dashboard, the domain's DNS page, and `docker compose logs unomail`. Set
`UNOMAIL_LOG=info,unomail=debug` for more detail.

| Symptom | Cause and fix |
| --- | --- |
| Outbound mail stays queued | Port 25 is blocked. Test with `nc -vz gmail-smtp-in.l.google.com 25`, then use a relay. |
| Mail lands in spam | Check SPF, DKIM, DMARC, the PTR record and blocklists. New IP addresses need time to build reputation. |
| DNSBL queries refused | The resolver is public. Add a `dns:` entry, or clear the blocklists in **Server settings**. |
| No certificate | Port 80 must be reachable and the hostname must resolve to the server. Otherwise use DNS-01. |
| Inbound mail delayed | Greylisting. Add trusted relays to `UNOMAIL_TRUSTED_NETWORKS`. |
| All clients have one private IP | Docker's userland proxy. Use host networking. |
| `451` replies | Rspamd or a milter is down. Fix it, or enable the `*_FAIL_OPEN` setting. |
