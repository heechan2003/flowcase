/*
The last minute the source holds detail for, from the day before the earliest match to now. A
source that keeps every loaded day may end before the wall clock does (older logs, a pinned demo);
the live phases then stop at its last loaded day instead of reading, and reporting as silent, days
it never loaded. One aggregate row, no identifier.
*/
SELECT max(time) AS last_minute
FROM flow.activity_1m
WHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
