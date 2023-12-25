import access
import auth
import searchf
import time

def main():
    auth.main()
    access.main()
    searchf.main()

if __name__ == "__main__":
    while True:
        print("log scaning...")
        main()
        print("log checked...")
        time.sleep(60)

