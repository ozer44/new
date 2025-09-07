#!/usr/bin/env python3
"""
Azure App Service startup script
"""
import os
import sys
from app import app

if __name__ == '__main__':
    # Azure App Service port configuration
    port = int(os.environ.get('PORT', 8001))
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=port,
        debug=False
    )
