#!/usr/bin/env python3
"""
ChatIDS Launcher - Simple script to start both watcher and webapp components
"""

import os
import sys
import subprocess
import argparse
import signal
import time
from multiprocessing import Process
from dotenv import load_dotenv 

# Load environment variables
load_dotenv()

def run_watcher(args):
    """Run the watcher component"""
    cmd = [sys.executable, 'watcher.py']
    
    # Use environment variable if no key provided
    gemini_key = args.gemini_key or os.getenv('GEMINI_API_KEY')
    if gemini_key:
        cmd.extend(['--gemini-key', gemini_key])
    
    if args.log_file:
        cmd.extend(['--log-file', args.log_file])
    if args.db_path:
        cmd.extend(['--db-path', args.db_path])
    if args.test_mode:
        cmd.append('--test-mode')
    
    print(f"Starting watcher: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("Watcher stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"Watcher failed with error: {e}")

def run_webapp(args):
    """Run the webapp component"""
    cmd = [sys.executable, 'webapp.py']
    
    if args.db_path:
        cmd.extend(['--db-path', args.db_path])
    if args.host:
        cmd.extend(['--host', args.host])
    if args.port:
        cmd.extend(['--port', str(args.port)])
    if args.debug:
        cmd.append('--debug')
    
    print(f"Starting webapp: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("Webapp stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"Webapp failed with error: {e}")

def main():
    parser = argparse.ArgumentParser(description='ChatIDS Launcher - Start both watcher and webapp')
    
    # Watcher arguments
    watcher_group = parser.add_argument_group('watcher options')
    watcher_group.add_argument('--gemini-key', default=os.getenv('GEMINI_API_KEY'),
                        help='Gemini API key (or set GEMINI_API_KEY environment variable)')
    watcher_group.add_argument('--log-file', default=os.getenv('LOG_FILE', '/var/log/suricata/eve.json'),
                        help='Path to Suricata eve.json log file')
    watcher_group.add_argument('--test-mode', action='store_true',
                        help='Use sample data for testing')
    
    # Webapp arguments
    webapp_group = parser.add_argument_group('webapp options')
    webapp_group.add_argument('--host', default=os.getenv('FLASK_HOST', '127.0.0.1'),
                        help='Host to bind webapp to')
    webapp_group.add_argument('--port', type=int, default=int(os.getenv('FLASK_PORT', 5000)),
                        help='Port for webapp')
    webapp_group.add_argument('--debug', action='store_true', default=os.getenv('DEBUG_MODE', 'False').lower() == 'true',
                        help='Run webapp in debug mode')
    
    # Common arguments
    parser.add_argument('--db-path', default=os.getenv('DATABASE_PATH', 'alerts.db'),
                        help='SQLite database path')
    parser.add_argument('--mode', choices=['both', 'watcher', 'webapp'], default='both',
                        help='Which components to run')
    
    args = parser.parse_args()
    
    # Check if API key is available
    if not args.gemini_key and 'both' in args.mode or 'watcher' in args.mode:
        print("Error: Gemini API key is required. Set GEMINI_API_KEY environment variable or use --gemini-key")
        sys.exit(1)
    
    
    # Check if required files exist
    if not os.path.exists('watcher.py'):
        print("Error: watcher.py not found in current directory")
        sys.exit(1)
    
    if not os.path.exists('webapp.py'):
        print("Error: webapp.py not found in current directory")
        sys.exit(1)
    
    print("ChatIDS Launcher")
    print("================")
    print(f"Mode: {args.mode}")
    print(f"Database: {args.db_path}")
    print(f"Gemini Key: {'***' + args.gemini_key[-4:] if len(args.gemini_key) > 4 else 'SET'}")
    
    if args.test_mode:
        print("Running in TEST MODE with sample data")
    
    print("\nPress Ctrl+C to stop all processes\n")
    
    processes = []
    
    try:
        if args.mode in ['both', 'watcher']:
            print("Starting watcher process...")
            watcher_process = Process(target=run_watcher, args=(args,))
            watcher_process.start()
            processes.append(('watcher', watcher_process))
            
            if args.test_mode:
                # Wait a moment for test mode to complete
                time.sleep(5)
        
        if args.mode in ['both', 'webapp']:
            print("Starting webapp process...")
            webapp_process = Process(target=run_webapp, args=(args,))
            webapp_process.start()
            processes.append(('webapp', webapp_process))
            
            print(f"\nWebapp should be available at: http://{args.host}:{args.port}")
        
        if processes:
            print(f"\nRunning {len(processes)} process(es). Press Ctrl+C to stop.\n")
            
            # Wait for processes to complete or be interrupted
            while any(p.is_alive() for name, p in processes):
                time.sleep(1)
    
    except KeyboardInterrupt:
        print("\nShutting down ChatIDS...")
        
        # Terminate all processes
        for name, process in processes:
            if process.is_alive():
                print(f"Stopping {name}...")
                process.terminate()
                process.join(timeout=5)
                
                if process.is_alive():
                    print(f"Force killing {name}...")
                    process.kill()
                    process.join()
        
        print("All processes stopped.")
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
