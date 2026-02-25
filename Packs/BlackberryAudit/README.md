This is the Blackberry Audit event collector integration for XSIAM.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Version 2.0.0
### Improvisations
- Event deduplication logic now uses timestamp comparison instead of string matching
- Overlap check function update from signle line to multi line code for easier understanding
- Error handling messages now include:
  - UUID
  - processed count
  - stack trace
- Update the error handling logic.
  - Error message now contains UUID, processed count, stack trace
  - Instead of putting all the code inside try-except block, put only the code where the error could occur (eg: fetching events from api, sending events to xsiam dataset)
  - Continue to next UUID in case of error in processing any UUID.