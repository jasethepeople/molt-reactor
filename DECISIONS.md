# Decisions

- Use `spot-signal/` as the separate SpotSignal workspace inside this repository, as the prompt's default directs.
- Treat Phase 4 as a local, testable MVP unless deployment credentials and a safe deployment target are already present. Do not publish real rough-sleeper locations or turn on activity alerts by default; location and report data are sensitive. Any external launch requires explicit review of privacy, retention, moderation, and abuse controls.
- Do not invent a name for the user's friend in the project dedication; acknowledge the friend as unnamed.
- Cap `max_trigger_depth` at 254 (rather than 255) so a `u8` child-depth increment cannot saturate and let a cycle evade its limit.
