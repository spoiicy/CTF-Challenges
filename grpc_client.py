import grpc
import testimonial_pb2
import testimonial_pb2_grpc

class TestimonialClient:
    def __init__(self, host='localhost:50045'):
        self.channel = grpc.insecure_channel(host)
        self.stub = testimonial_pb2_grpc.TestimonialServiceStub(self.channel)
    
    def send_testimonial(self, customer, testimonial):
        # CLIENT-SIDE FILTERING (can be bypassed)
        bad_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '.']
        for char in bad_chars:
            customer = customer.replace(char, '')
        
        request = testimonial_pb2.TestimonialSubmission(
            customer=customer,
            testimonial=testimonial
        )
        
        response = self.stub.SubmitTestimonial(request)
        return response.message