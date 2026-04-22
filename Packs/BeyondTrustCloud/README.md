This is the Beyontrust Cloud event collector integration for XSIAM.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Version 2.0.0
### Improvisations
- Removed the SessionParser class that was previously used to convert XML data to JSON.
- Added the Python module xmltodict to convert XML responses directly into JSON format before pushing the data to the XSIAM dataset.

## Version 2.1.0
### Updates
- Add raw  xml log into dataset when XML → JSON conversion fails:
  - When conversion fails, the raw XML payload is now logged in the dataset under the `_raw_log` field for debugging and traceability.
- Implemented regex-based extraction as a secondary fallback in case of conversion failure:
  - Extracts `lseq` and `end_time` timestamp directly from the XML when parsing fails.
  - Update the integration context to prevent duplicate logging of the same failed payload in the dataset.