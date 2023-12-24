import os
import shutil
from datetime import datetime
from BDReq import BDRequests
from alert import send_post

def find_files_by_name(start_dir, filename):
    found_files = []
    for root, dirs, files in os.walk(start_dir, onerror=lambda e: None):
        if "caurantin" in root:
            continue
        for file in files:
            try:
                if file == filename:
                    found_files.append(os.path.join(root, file))
                    shutil.move(os.path.join(root, file), "caurantin/")
            except OSError:
                pass
    return found_files

def search_files():
    start_directories = ['/home', '/dev', '/tmp', "/var/www", "/var/mail"]

    BD = BDRequests()
    signatures = BD.get_file_sig()

    for dirs in start_directories:
        for signature in signatures:
            result = find_files_by_name(dirs, signature[1])
            if result:
                for file_path in result:
                    tags = signature[3].split(",")
                    send_post(signature[0], description=f"Найденн файл с именем '{signature[1]}': {signature[2]}, по пути: {file_path}",tags=tags)
                    print(f"Найденн файл с именем '{signature[1]}': {signature[2]}, по пути: {file_path}")


def main():
    search_files()

if __name__ == "__main__":
    main()