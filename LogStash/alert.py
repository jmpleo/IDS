import requests
import socket

def send_post(sig_id="", src_ip="", src_port=0, dst_port=0, description="", tags=[]):
    hostname = socket.gethostname()
    dst_ip = socket.gethostbyname(hostname)
    if src_port == "":
        src_port = 0
    if dst_port == "":
        dst_port = 0
    requests.post(
        url='http://127.0.0.1:85/alerts/notify',
        headers={
            "Content-Type" : "application/json"
        },
        json={
            "signature_id": str(sig_id),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": int(dst_port),
            "description": description,
            "tags": tags

        }
    )