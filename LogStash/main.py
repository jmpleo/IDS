import access
import auth
import searchf

def main():
    print("log scaning...")
    auth.main()
    access.main()
    searchf.main()
    print("log checked...")

if __name__ == "__main__":
    main()

