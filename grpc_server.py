import grpc
from concurrent import futures
import testimonial_pb2
import testimonial_pb2_grpc
import os
import traceback

class TestimonialService(testimonial_pb2_grpc.TestimonialServiceServicer):
    def SubmitTestimonial(self, request, context):
        try:
            print(f"Received testimonial submission:")
            print(f"Customer: '{request.customer}'")
            print(f"Content: '{request.testimonial}'")
            
            if not request.customer:
                return testimonial_pb2.GenericReply(message="Error: Customer name is required")
            
            if not request.testimonial:
                return testimonial_pb2.GenericReply(message="Error: Testimonial content is required")
            
            os.makedirs('templates/testimonials', exist_ok=True)
            
            file_path = f"templates/testimonials/{request.customer}"
            print(f"Writing to: {file_path}")
            
            with open(file_path, 'w') as f:
                f.write(request.testimonial)
            
            # Verify file was written
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                print(f"File written successfully! Size: {file_size} bytes")
            else:
                print("File was not created!")
            
            return testimonial_pb2.GenericReply(message="Testimonial submitted successfully!")
            
        except Exception as e:
            error_msg = f"Server error: {str(e)}"
            print(f"ERROR: {error_msg}")
            print(traceback.format_exc())
            return testimonial_pb2.GenericReply(message=error_msg)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    testimonial_pb2_grpc.add_TestimonialServiceServicer_to_server(
        TestimonialService(), server
    )
    server.add_insecure_port('[::]:50045')
    print("gRPC Server running on port 50045")
    print("Testimonials will be saved to: templates/testimonials/")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()