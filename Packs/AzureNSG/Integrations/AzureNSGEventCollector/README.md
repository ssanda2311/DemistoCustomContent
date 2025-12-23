## 🔐 Authentication Methods for NSG Integration

To enable secure communication between Cortex XSIAM and your NSG (Network Security Group) data source, authentication is required using a **connection string** and **container name**. These credentials allow Cortex to access and ingest logs or configuration data from your storage backend.

### 📦 Required Parameters

- **Connection String**  
  This string contains the credentials and endpoint information needed to access your storage account. It typically includes the account name, key, and endpoint suffix.

- **Container Name**  
  The name of the blob container where NSG logs or configuration files are stored. Ensure the container is publicly accessible or that the connection string has sufficient permissions.

---

## 🔧 Setup Instructions

1. **Obtain Connection String**  
   - Navigate to your Azure Storage Account.
   - Go to **Access Keys** under **Security + Networking**.
   - Copy the **Connection String** for either key1 or key2.

2. **Identify Container Name**  
   - Go to **Containers** under **Data Storage**.
   - Select the container where NSG logs are stored.
   - Copy the container name exactly as it appears.

3. **Configure in Cortex XSIAM**  
   - Open the NSG integration instance.
   - Paste the connection string into the **Connection String** field.
   - Enter the container name in the **Container Name** field.
   - Save and test the connection.

---

## 🛡️ Permissions & Access Control

Ensure the connection string has **read access** to the container. If using a **Shared Access Signature (SAS)** token instead of a full connection string, make sure it includes:
- `Blob` service access
- `Read` permission
- Valid expiry date

---


## 🧪 Testing the Integration

After configuration:
- Use the **Test ** button to verify access.
- Confirm that logs are ingested successfully.
- Check the Cortex XSIAM dataset for NSG-related logs.

