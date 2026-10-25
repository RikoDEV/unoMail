// Removing a built-in feature: the calendar disappears from the navigation and its address
// leads back to the mail. A page of the plug-in's own takes its place.
const context = await unomail.ready;

if (context.view === 'agenda') {
  document.body.style.padding = '16px';
  document.body.textContent = 'The calendar is turned off on this server. Ask your team for the meeting schedule.';
} else {
  await unomail.features.hide('calendar');
  await unomail.ui.mount({ slot: 'app.navigation', id: 'agenda', title: 'Agenda' });
}
