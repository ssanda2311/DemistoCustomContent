This is the Azure DevOps event collector integration for XSIAM.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Crowdstrike FIM Event Collector on Cortex:
1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for Azure DevOps Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL                  | True |
    | Auth URL                    | True |
    | Client ID                   | True |
    | Client Secret               | True |
    | Tenant ID                   | True |
    | Scope                       | True |
    | Organization                | True |

4. Click **Test** to validate the URLs, token, and connection