-- Daily counters for the dashboard: SMTP connections (valid, blocked, limited) and what became
-- of mail (delivered locally or remotely, bounced, quarantined, discarded). `day` is the UTC
-- day number (unix seconds / 86400). Kept far longer than the delivery log they summarise.
CREATE TABLE daily_stats (
    day    INTEGER NOT NULL,
    metric TEXT NOT NULL,
    count  INTEGER NOT NULL,
    PRIMARY KEY (day, metric)
) STRICT, WITHOUT ROWID;

-- The deliveries still in the log are counted at once, so the chart has a history from the start.
INSERT INTO daily_stats (day, metric, count)
SELECT day, metric, count(*) FROM (
    SELECT ts / 86400 AS day,
           CASE
               WHEN status = 'delivered' AND direction = 'outbound' THEN 'delivered_remote'
               WHEN status = 'delivered' THEN 'delivered_local'
               WHEN status IN ('bounced', 'rejected') THEN 'bounced'
               WHEN status = 'junk' THEN 'quarantined'
               WHEN status = 'discarded' THEN 'discarded'
           END AS metric
    FROM delivery_log
) WHERE metric IS NOT NULL
GROUP BY day, metric;
