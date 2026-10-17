-- Periodic samples of the host's resources, for the capacity charts on the dashboard.
CREATE TABLE system_samples (
    ts         INTEGER PRIMARY KEY,
    disk_free  INTEGER NOT NULL,                               -- bytes free on the data volume
    disk_total INTEGER NOT NULL,
    mem_used   INTEGER NOT NULL,                               -- bytes of memory in use on the host
    mem_total  INTEGER NOT NULL,
    process    INTEGER NOT NULL                                -- resident memory of the server process
) STRICT;
