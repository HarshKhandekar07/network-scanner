from flask import Flask, render_template, jsonify, request, Response
import json
import queue
import threading
import os
import sys

# Ensure network-scanner folder is in the Python path so imports work perfectly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner import get_local_ip, get_default_subnet, scan_network

app = Flask(__name__, template_folder='templates', static_folder='static')

@app.route('/')
def index():
    """
    Renders the web dashboard frontend.
    """
    return render_template('index.html')

@app.route('/api/info', methods=['GET'])
def info():
    """
    Returns the auto-detected local IP and default recommended subnet range.
    """
    try:
        local_ip = get_local_ip()
        default_subnet = get_default_subnet()
        return jsonify({
            "status": "success",
            "local_ip": local_ip,
            "default_subnet": default_subnet
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/scan/stream', methods=['GET'])
def scan_stream():
    """
    Server-Sent Events (SSE) endpoint to stream network scanning progress
    and active host discoveries to the frontend in real-time.
    """
    target = request.args.get('target', '').strip()
    if not target:
        return jsonify({"status": "error", "message": "Target parameter is required"}), 400

    # Thread-safe queue to pass messages from scanner thread to SSE generator
    q = queue.Queue()

    def progress_callback(progress_data):
        # Callback triggered by scan_network after each IP ping attempt
        q.put(("progress", progress_data))

    def run_scan():
        try:
            # Execute scan with parallel execution threads
            results = scan_network(target, progress_callback=progress_callback, thread_count=64)
            q.put(("complete", results))
        except Exception as e:
            q.put(("error", str(e)))

    # Spin scanner off in a daemon thread so it runs concurrently with the client streaming loop
    threading.Thread(target=run_scan, daemon=True).start()

    def event_stream():
        while True:
            try:
                # Poll the queue for updates (with 20-second timeout to prevent stalling)
                msg_type, payload = q.get(timeout=20)
                
                if msg_type == "progress":
                    yield f"event: progress\ndata: {json.dumps(payload)}\n\n"
                elif msg_type == "complete":
                    yield f"event: complete\ndata: {json.dumps(payload)}\n\n"
                    break
                elif msg_type == "error":
                    yield f"event: error\ndata: {json.dumps({'message': payload})}\n\n"
                    break
            except queue.Empty:
                # Send keep-alive comments to prevent nginx/browser timeouts
                yield ": keep-alive\n\n"
            except GeneratorExit:
                # Client closed connection unexpectedly
                break

    return Response(event_stream(), mimetype="text/event-stream")

if __name__ == '__main__':
    # Start local Flask application on port 5001 (avoids macOS AirPlay Receiver port 5000 conflict)
    app.run(host='127.0.0.1', port=5001, debug=True)

