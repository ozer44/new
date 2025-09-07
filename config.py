import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class DatabaseConfig:
    """Database configuration management for dual SQL Server connections"""
    
    def __init__(self):
        self.database_type = os.getenv('DATABASE_TYPE', 'local')
        
        # Local SQL Server Configuration
        self.local_config = {
            'DRIVER': os.getenv('LOCAL_DRIVER', '{ODBC Driver 17 for SQL Server}'),
            'SERVER': os.getenv('LOCAL_SERVER', 'DESKTOP-E62JOKI\\SQLEXPRESS'),
            'DATABASE': os.getenv('LOCAL_DATABASE', 'mbo-mft'),
            'UID': os.getenv('LOCAL_UID', 'mft_user'),
            'PWD': os.getenv('LOCAL_PWD', '123456')
        }
        
        # Azure SQL Server Configuration
        self.azure_config = {
            'DRIVER': os.getenv('AZURE_DRIVER', '{ODBC Driver 17 for SQL Server}'),
            'SERVER': os.getenv('AZURE_SERVER', 'mftsql2.database.windows.net'),
            'DATABASE': os.getenv('AZURE_DATABASE', 'mbo-mft'),
            'UID': os.getenv('AZURE_UID', 'mft_user'),
            'PWD': os.getenv('AZURE_PWD', 'Pp123456Pp123456')
        }
    
    def get_active_config(self):
        """Get the currently active database configuration"""
        if self.database_type.lower() == 'azure':
            return self.azure_config
        else:
            return self.local_config
    
    def get_connection_string(self, config_type=None):
        """Generate connection string for specified database type"""
        from urllib.parse import quote_plus
        
        if config_type is None:
            config = self.get_active_config()
        elif config_type.lower() == 'azure':
            config = self.azure_config
        else:
            config = self.local_config
        
        conn_str = ';'.join(f"{k}={v}" for k, v in config.items())
        return f"mssql+pyodbc:///?odbc_connect={quote_plus(conn_str)}"
    
    def test_connection(self, config_type=None):
        """Test database connection for specified type"""
        try:
            from sqlalchemy import create_engine
            test_uri = self.get_connection_string(config_type)
            engine = create_engine(test_uri, pool_pre_ping=True)
            connection = engine.connect()
            connection.close()
            return True, "Connection successful"
        except Exception as e:
            return False, str(e)
    
    def validate_config(self, config_type=None):
        """Validate database configuration"""
        if config_type is None:
            config = self.get_active_config()
        elif config_type.lower() == 'azure':
            config = self.azure_config
        else:
            config = self.local_config
        
        required_fields = ['DRIVER', 'SERVER', 'DATABASE', 'UID', 'PWD']
        missing_fields = [field for field in required_fields if not config.get(field)]
        
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}"
        
        return True, "Configuration valid"
    
    def switch_database(self, database_type):
        """Switch to specified database type"""
        if database_type.lower() in ['local', 'azure']:
            self.database_type = database_type.lower()
            return True
        return False
    
    def get_database_info(self):
        """Get information about current database configuration"""
        config = self.get_active_config()
        return {
            'type': self.database_type,
            'server': config['SERVER'],
            'database': config['DATABASE'],
            'user': config['UID']
        }
