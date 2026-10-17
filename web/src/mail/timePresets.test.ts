import { describe, expect, it } from 'vitest';
import { schedulePresets, snoozePresets } from './timePresets';

describe('time presets', () => {
  it('schedules for the next working mornings', () => {
    // Wednesday 14 October 2026, 10:30.
    const now = new Date(2026, 9, 14, 10, 30);
    const [tomorrow, afternoon, monday] = schedulePresets(now);
    expect(tomorrow.at).toEqual(new Date(2026, 9, 15, 8, 0));
    expect(afternoon.at).toEqual(new Date(2026, 9, 15, 13, 0));
    expect(monday.at).toEqual(new Date(2026, 9, 19, 8, 0));
  });

  it('snoozes until later today, tomorrow, the weekend or next week', () => {
    const wednesday = snoozePresets(new Date(2026, 9, 14, 10, 30));
    expect(wednesday.map((p) => p.label)).toEqual(['Later today', 'Tomorrow', 'This weekend', 'Next week']);
    expect(wednesday[0].at).toEqual(new Date(2026, 9, 14, 18, 0));
    expect(wednesday[2].at).toEqual(new Date(2026, 9, 17, 8, 0));
    // Late in the evening there is no "later today"; on Saturday no "this weekend".
    expect(snoozePresets(new Date(2026, 9, 14, 21, 0)).map((p) => p.label)).toEqual(['Tomorrow', 'This weekend', 'Next week']);
    const saturday = snoozePresets(new Date(2026, 9, 17, 9, 0));
    expect(saturday.map((p) => p.label)).toEqual(['Later today', 'Tomorrow', 'Next week']);
    expect(saturday[2].at).toEqual(new Date(2026, 9, 19, 8, 0));
  });
});
