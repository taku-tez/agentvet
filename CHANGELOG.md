# Changelog

## [0.20.1] - 2026-03-19

### Added
- **tool-poison-encoded-payload**: Detect base64/hex-encoded obfuscated injection payloads in tool outputs
- **tool-poison-markdown-exfiltration**: Detect markdown image/link data exfiltration via URL parameters
- **tool-poison-tool-redirection**: Detect tool outputs that instruct the agent to call other tools (tool chaining attacks)
- **tool-poison-callback-exfiltration**: Detect tool outputs requesting HTTP callbacks to external URLs for data exfiltration
- **tool-poison-history-manipulation**: Detect tool outputs attempting to manipulate or rewrite conversation history/context
- 40 new tests for the 5 new rules (8 tests each)

## [0.20.0] - Previous release
- 1729 tests, 37 rule modules, 10 tool-poisoning rules
