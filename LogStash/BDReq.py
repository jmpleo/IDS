import psycopg2
import os

class BDRequests():
    def __init__(self):
        self.conn = psycopg2.connect(database=os.getenv("DATABASE_NAME"), user=os.getenv("DATABASE_USER"), password=os.getenv("DATABASE_PASSWORD"), host=os.getenv("DATABASE_HOSTNAME"), port=os.getenv("DATABASE_PORT"))

    def __del__(self):
        self.conn.close()

    def get_signatures(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM acces_log_signature;", )
        signatures = cur.fetchall() 
        cur.close()
        return signatures


    def get_fuzzer_sig(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM fuzzers_signature;", )
        signatures = cur.fetchall() 
        cur.close()
        return signatures
    
    def get_file_sig(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM files_signature;", )
        signatures = cur.fetchall() 
        cur.close()
        return signatures