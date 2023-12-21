import requests
import socket

def send_post(sig_id="", src_ip="", src_port="", dst_port="", description="", tags=[]):
    hostname = socket.gethostname()
    dst_ip = socket.gethostbyname(hostname)
    
    # requests.post(
    #     url='http://127.0.0.1/alerts/notify/',
    #     headers={
    #         "Content-Type" : "application/json"
    #     },
    #     json={
    #         "signature_id": sig_id,
    #         "source_ip": src_ip,
    #         "destination_ip": dst_ip,
    #         "source_port": src_port,
    #         "destination_port": dst_port,
    #         "description": description,
    #         "timestamp": timestamp,
    #         "tags": tags
    #     }
    # )