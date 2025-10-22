from flask import Flask, request, render_template, send_from_directory
import grpc_client
import os
import glob

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

def get_recent_testimonials():
    """Read and return recent testimonials from the filesystem"""
    testimonials = []
    testimonials_dir = 'templates/testimonials'
    
    if not os.path.exists(testimonials_dir):
        return testimonials
    
    # Get all files in testimonials directory
    testimonial_files = glob.glob(os.path.join(testimonials_dir, '*'))
    
    for file_path in testimonial_files[:10]:  # Show last 10 testimonials
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r') as f:
                    content = f.read().strip()
                # Use filename as customer name, but remove path
                customer = os.path.basename(file_path)
                testimonials.append({
                    'customer': customer,
                    'content': content
                })
            except Exception as e:
                print(f"Error reading testimonial {file_path}: {e}")
    
    return testimonials

@app.route('/')
def index():
    customer = request.args.get('customer', '')
    testimonial = request.args.get('testimonial', '')
    
    if customer and testimonial:
        try:
            client = grpc_client.TestimonialClient()
            result = client.send_testimonial(customer, testimonial)
            print(f"Testimonial submission result: {result}")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    # Get recent testimonials to display
    recent_testimonials = get_recent_testimonials()
    print(f"Found {len(recent_testimonials)} testimonials")
    
    return render_template('index.html', testimonials=recent_testimonials)

@app.route('/testimonials/<path:filename>')
def get_testimonial(filename):
    return send_from_directory('templates/testimonials', filename)


if __name__ == '__main__':
    # Create testimonials directory if it doesn't exist
    os.makedirs('templates/testimonials', exist_ok=True)
    
    # Start gRPC server in background
    import subprocess
    import threading
    import time
    
    def start_grpc_server():
        print("Starting gRPC server...")
        subprocess.run(['python', 'grpc_server.py'])
    
    grpc_thread = threading.Thread(target=start_grpc_server)
    grpc_thread.daemon = True
    grpc_thread.start()
    
    # Give gRPC server time to start
    time.sleep(2)
    
    print("Starting Flask app on http://localhost:1337")
    print("Debug info available at http://localhost:1337/debug")
    app.run(host='0.0.0.0', port=1337, debug=True)