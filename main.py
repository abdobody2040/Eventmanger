
from app import app
import os

if __name__ == '__main__':
    # Get configuration from .env
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', '4000'))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

    print(f"Starting Flask server on {host}:{port} (debug={debug})")
    try:
        app.run(host=host, port=port, debug=debug)
    except Exception as e:
        print(f"Error starting Flask server: {e}")
        import traceback
        traceback.print_exc()
