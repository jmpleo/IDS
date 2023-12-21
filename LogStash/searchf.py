import os
from datetime import datetime
from BDReq import BDRequests
from alert import send_post

def find_files_by_name(start_dir, filename):
    found_files = []
    for root, dirs, files in os.walk(start_dir, onerror=lambda e: None):
        for file in files:
            try:
                if file == filename:
                    found_files.append(os.path.join(root, file))
            except OSError:
                pass
    return found_files

def search_files():
    # Пример использования:
    start_directories = ['/home', '/dev', '/tmp', '/var']

    BD = BDRequests()
    signatures = BD.get_file_sig()

    for dirs in start_directories:
        for signature in signatures:
            result = find_files_by_name(dirs, signature[1])
            if result:
                for file_path in result:
                    send_post(signature[0],"local", "local", "local", f"Найденн файл с именем '{signature[1]}': {signature[2]}, по пути: {file_path}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    print(f"Найденн файл с именем '{signature[1]}': {signature[2]}, по пути: {file_path}")


def main():
    search_files()

if __name__ == "__main__":
    main()