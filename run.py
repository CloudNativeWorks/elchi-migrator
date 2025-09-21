#!/usr/bin/env python3
try:
    from dotenv import load_dotenv
    # Load environment variables from .env file
    load_dotenv()
    import os
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print("DEBUG: .env file loaded successfully")
except ImportError:
    import os
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print("DEBUG: python-dotenv not installed, using system environment variables")
except Exception as e:
    import os
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: Could not load .env file: {e}, using system environment variables")

from app import create_app

if __name__ == '__main__':
    app = create_app()
    
    # Background stats removed - use Flask web interface instead
    print("📋 Use Flask web interface with nocache parameter to update VServer data")
    
    app.run(
        host='0.0.0.0',
        port=5001,
        debug=True
    )