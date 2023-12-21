import os

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

def main():
    # Пример использования:
    start_directories = ['/home', '/dev', '/tmp', '/var']
    search_filename = 'alert.py'  # Имя искомого файла

    for dirs in start_directories:
        result = find_files_by_name(dirs, search_filename)
        if result:
            for file_path in result:
                print(f"Найденные файлы с именем '{search_filename}': {file_path}")

if __name__ == "__main__":
    main()