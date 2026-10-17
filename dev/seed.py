#!/usr/bin/env python3
"""Fills a development server with sample data: two extra mailboxes and a varied inbox.

Usage (with the dev server from the README running):

    python dev/seed.py

Environment: UNOMAIL_DEV_URL (default http://127.0.0.1:8080), UNOMAIL_DEV_SMTP_PORT (2525),
UNOMAIL_ADMIN_EMAIL (admin@example.test), UNOMAIL_ADMIN_PASSWORD (dev-password-123).
Running it again adds another copy of the sample mail; the sample calendar events are replaced.
"""

import base64
import datetime
import json
import os
import smtplib
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

BASE = os.environ.get('UNOMAIL_DEV_URL', 'http://127.0.0.1:8080')
SMTP_PORT = int(os.environ.get('UNOMAIL_DEV_SMTP_PORT', '2525'))
ADMIN = os.environ.get('UNOMAIL_ADMIN_EMAIL', 'admin@example.test')
PASSWORD = os.environ.get('UNOMAIL_ADMIN_PASSWORD', 'dev-password-123')
DOMAIN = ADMIN.split('@')[1]
USER_PASSWORD = 'dev-password-123'

session = {'cookie': '', 'csrf': ''}


def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        request.add_header('Content-Type', 'application/json')
    if session['cookie']:
        request.add_header('Cookie', session['cookie'])
    if method != 'GET':
        request.add_header('X-CSRF-Token', session['csrf'])
    try:
        with urllib.request.urlopen(request) as response:
            cookie = response.headers.get('Set-Cookie')
            if cookie and not session['cookie']:
                session['cookie'] = cookie.split(';')[0]
            return response.status, json.loads(response.read().decode() or 'null')
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode('utf-8', 'replace')


def tiny_pdf(text):
    stream = f'BT /F1 20 Tf 40 150 Td ({text}) Tj ET'
    objects = [
        '<< /Type /Catalog /Pages 2 0 R >>',
        '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 420 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
        f'<< /Length {len(stream)} >>\nstream\n{stream}\nendstream',
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    ]
    body, offsets = '%PDF-1.4\n', []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(body))
        body += f'{number} 0 obj\n{obj}\nendobj\n'
    xref = len(body)
    body += f'xref\n0 {len(objects) + 1}\n0000000000 65535 f \n' + ''.join(f'{offset:010d} 00000 n \n' for offset in offsets)
    body += f'trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'
    return body.encode('latin-1')


PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==')


def message(sender, name, to, subject, text, html=None, attachments=(), reply_to=None, references=None, headers=None):
    mail = EmailMessage()
    for key, value in (headers or {}).items():
        mail[key] = value
    mail['From'] = f'{name} <{sender}>'
    mail['To'] = to
    mail['Subject'] = subject
    mail['Date'] = formatdate(localtime=True)
    mail['Message-ID'] = make_msgid(domain=sender.split('@')[1])
    if reply_to:
        mail['In-Reply-To'] = reply_to
        mail['References'] = references or reply_to
    mail.set_content(text)
    if html:
        mail.add_alternative(html, subtype='html')
    for filename, kind, data in attachments:
        maintype, subtype = kind.split('/')
        mail.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return mail


def deliver(mail, recipient):
    with smtplib.SMTP('127.0.0.1', SMTP_PORT, local_hostname='mail.remote.example') as smtp:
        smtp.send_message(mail, from_addr=mail['From'].addresses[0].addr_spec, to_addrs=[recipient])


def calendar_events(user):
    """Stores a few events through CalDAV, the way a calendar program would."""
    today = datetime.date.today()
    monday = today - datetime.timedelta(days=today.weekday())
    later = lambda days: today + datetime.timedelta(days=days)
    stamp = lambda day, hour, minute=0: f'{day:%Y%m%d}T{hour:02d}{minute:02d}00'
    zone = 'TZID=Europe/Warsaw'
    events = {
        'standup': [f'DTSTART;{zone}:{stamp(monday, 9, 30)}', 'DURATION:PT15M', 'RRULE:FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR', 'SUMMARY:Stand-up', 'LOCATION:Video call'],
        'lunch': [f'DTSTART;{zone}:{stamp(today, 12, 30)}', f'DTEND;{zone}:{stamp(today, 13, 30)}', 'SUMMARY:Lunch with Anna', 'LOCATION:Bistro on the corner'],
        'review': [f'DTSTART;{zone}:{stamp(later(2), 14)}', f'DTEND;{zone}:{stamp(later(2), 15, 30)}', 'SUMMARY:Quarterly review', 'DESCRIPTION:Numbers\\, hiring\\, roadmap'],
        'conference': [f'DTSTART;VALUE=DATE:{later(6):%Y%m%d}', f'DTEND;VALUE=DATE:{later(8):%Y%m%d}', 'SUMMARY:Mail conference', 'LOCATION:Kraków'],
    }
    token = base64.b64encode(f'{user}:{USER_PASSWORD}'.encode()).decode()
    for name, properties in events.items():
        now = datetime.datetime.now(datetime.timezone.utc)
        ics = '\r\n'.join(['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//unoMail//Dev seed//EN', 'BEGIN:VEVENT', f'UID:seed-{name}@{DOMAIN}', f'DTSTAMP:{now:%Y%m%dT%H%M%SZ}',
                           *properties, 'END:VEVENT', 'END:VCALENDAR', ''])
        request = urllib.request.Request(f'{BASE}/dav/calendars/{user}/personal/seed-{name}.ics', data=ics.encode(), method='PUT')
        request.add_header('Authorization', f'Basic {token}')
        request.add_header('Content-Type', 'text/calendar; charset=utf-8')
        try:
            urllib.request.urlopen(request).close()
        except urllib.error.HTTPError as error:
            print(f'calendar event {name} for {user}: {error.code}')
            return
    print(f'{len(events)} calendar events stored for {user}')



def main():
    status, login = api('POST', '/api/auth/login', {'email': ADMIN, 'password': PASSWORD})
    if status != 200:
        raise SystemExit(f'Could not sign in as {ADMIN} at {BASE}: {login}')
    session['csrf'] = login['csrf_token']

    status, created = api('POST', '/api/domains', {'name': DOMAIN})
    print(f'domain {DOMAIN}:', 'created' if status == 200 else 'already there')
    for local, name in [('alice', 'Alice Example'), ('bob', 'Bob Example')]:
        status, _ = api('POST', '/api/accounts', {'email': f'{local}@{DOMAIN}', 'display_name': name, 'password': USER_PASSWORD})
        print(f'mailbox {local}@{DOMAIN}:', 'created' if status == 200 else 'already there')
    status, _ = api('POST', '/api/aliases', {'source': f'team@{DOMAIN}', 'destinations': [ADMIN, f'alice@{DOMAIN}']})
    print(f'alias team@{DOMAIN}:', 'created' if status == 200 else 'already there')

    newsletter = f'''<div style="font-family:sans-serif;max-width:560px">
<h2 style="color:#6750a4">This week at Example Corp</h2>
<p>Hello,</p><p>Our autumn release is out. Highlights:</p>
<ul><li><b>Faster search</b> across all folders</li><li>Shared folders for teams</li><li>End-to-end encryption</li></ul>
<p><img src="https://picsum.photos/seed/unomail/520/180" alt="Release banner" width="520"></p>
<p><a href="https://example.com/release-notes">Read the release notes</a></p>
<p style="color:#888;font-size:12px">You receive this because you subscribed. <a href="https://example.com/unsubscribe">Unsubscribe</a></p></div>'''

    for recipient in [ADMIN, f'alice@{DOMAIN}', f'bob@{DOMAIN}']:
        first = message('anna.kowalska@partner.example', 'Anna Kowalska', recipient, 'Quarterly report and next steps',
                        'Hi,\n\nplease find the quarterly report attached. Could we talk on Thursday?\n\nBest regards,\nAnna',
                        attachments=[('report-q3.pdf', 'application/pdf', tiny_pdf('Quarterly report Q3')),
                                     ('notes.txt', 'text/plain', 'Agenda for Thursday\n- numbers\n- hiring\n- roadmap\n'.encode()),
                                     ('figures.csv', 'text/csv', b'month,revenue\nJuly,120\nAugust,135\nSeptember,151\n')])
        deliver(first, recipient)
        deliver(message('anna.kowalska@partner.example', 'Anna Kowalska', recipient, 'Re: Quarterly report and next steps',
                        'One more thing: the meeting room is booked from 10:00.\n\nAnna', reply_to=first['Message-ID']), recipient)
        deliver(message('news@newsletter.example', 'Example Corp News', recipient, 'This week at Example Corp', 'Our autumn release is out.', html=newsletter,
                        headers={'List-Unsubscribe': '<mailto:unsubscribe@newsletter.example?subject=unsubscribe>, <https://newsletter.example/unsubscribe>'}), recipient)
        deliver(message('dev@lists.example', 'Dev list', recipient, '[dev] RFC: plug-in API v2', 'Comments welcome until Friday.',
                        headers={'List-Id': '<dev.lists.example>', 'List-Post': '<mailto:dev@lists.example>', 'List-Unsubscribe': '<mailto:dev-leave@lists.example>'}), recipient)
        deliver(message('invitations@linkedin.com', 'LinkedIn', recipient, 'You have 3 new invitations', 'See who wants to connect.'), recipient)
        deliver(message('jan.nowak@remote.example', 'Jan Nowak', recipient, 'Zażółć gęślą jaźń: test polskich znaków',
                        'Cześć,\n\nczy wszystkie znaki wyświetlają się poprawnie? ąćęłńóśźż ĄĆĘŁŃÓŚŹŻ\n\nPozdrawiam,\nJan'), recipient)
        deliver(message('builds@ci.example', 'CI', recipient, '[unomail] Build #482 passed',
                        'All 213 tests passed in 4m 12s.\n\nCommit: 96fce99 Make the DNS-01 ACME test deterministic\n',
                        attachments=[('build.log', 'text/plain', ('step 1/6 ok\n' * 40).encode())]), recipient)
        deliver(message('photos@family.example', 'Marta', recipient, 'Photos from the weekend', 'A few pictures from the lake. The big ones follow by link.',
                        html='<p>A few pictures from the lake. The big ones follow by link.</p>', attachments=[('lake.png', 'image/png', PNG), ('archive.zip', 'application/zip', b'PK\x03\x04sample')]), recipient)
        deliver(message('billing@hosting.example', 'Hosting Billing', recipient, 'Invoice 2026-10 is ready',
                        'Your invoice for October is attached.\n\nAmount due: 12.00 EUR\nDue date: 2026-10-31\n',
                        attachments=[('invoice-2026-10.pdf', 'application/pdf', tiny_pdf('Invoice 2026-10: 12.00 EUR'))]), recipient)
        print(f'9 messages delivered to {recipient}')

    for user in [ADMIN, f'alice@{DOMAIN}', f'bob@{DOMAIN}']:
        calendar_events(user)

    # One message through the alias, and one that the server refuses (shows up on the dashboard).
    deliver(message('customer@shop.example', 'A Customer', f'team@{DOMAIN}', 'Question about my order', 'Hello team,\n\nwhere is my order #1234?\n'), f'team@{DOMAIN}')
    try:
        deliver(message('stranger@remote.example', 'Stranger', f'nobody@{DOMAIN}', 'Is anyone there?', 'Hello?'), f'nobody@{DOMAIN}')
    except smtplib.SMTPException:
        pass
    print(f'\nSign in at the dev client with {ADMIN} / {PASSWORD}')
    print(f'or as alice@{DOMAIN} / bob@{DOMAIN} with the password {USER_PASSWORD}')


if __name__ == '__main__':
    main()
