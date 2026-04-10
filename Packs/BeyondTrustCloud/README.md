This is the Beyontrust Cloud event collector integration for XSIAM.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Version 2.0.0
### Improvisations
- Removed the SessionParser class that was previously used to convert XML data to JSON.
- Added the Python module xmltodict to convert XML responses directly into JSON format before pushing the data to the XSIAM dataset.