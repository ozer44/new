# Database Configuration Guide

This application now supports dual SQL Server connections - one for local and one for Azure SQL Server. You can easily switch between them through the web interface.

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Database Configuration
# Set to 'local' or 'azure' to choose which database to use
DATABASE_TYPE=local

# Local SQL Server Configuration
LOCAL_SERVER=DESKTOP-E62JOKI\SQLEXPRESS
LOCAL_DATABASE=mbo-mft
LOCAL_UID=mft_user
LOCAL_PWD=123456
LOCAL_DRIVER={ODBC Driver 17 for SQL Server}

# Azure SQL Server Configuration
AZURE_SERVER=mftsql2.database.windows.net
AZURE_DATABASE=mbo-mft
AZURE_UID=mft_user
AZURE_PWD=Pp123456Pp123456
AZURE_DRIVER={ODBC Driver 17 for SQL Server}

# Application Configuration
SECRET_KEY=your-secret-key
```

## Features

### 1. Dual Database Support
- **Local SQL Server**: For development and local testing
- **Azure SQL Server**: For production and cloud deployment

### 2. Web Interface Management
- Access through "Veritabanı Ayarları" (Database Settings) in the admin menu
- Switch between databases with a single click
- Test connections before switching
- View current database information

### 3. Configuration Management
- Environment variable based configuration
- Easy to modify without code changes
- Validation of configuration parameters

## Usage

1. **Configure Environment Variables**: Set up your `.env` file with the appropriate database credentials
2. **Access Database Settings**: Log in as admin and go to "Veritabanı Ayarları"
3. **Test Connections**: Use the "Test Connection" button to verify connectivity
4. **Switch Databases**: Use the "Switch to Local/Azure" buttons to change the active database

## Important Notes

- Both databases should have the same schema structure
- Test connections before switching to ensure connectivity
- Database switching affects the entire application
- Configuration changes require application restart for environment variables

## Troubleshooting

### Connection Issues
- Verify ODBC Driver 17 for SQL Server is installed
- Check firewall settings for Azure connections
- Ensure database credentials are correct
- Test connections through the web interface

### Configuration Issues
- Ensure all required environment variables are set
- Check for typos in server names and credentials
- Verify database names exist on the target servers
