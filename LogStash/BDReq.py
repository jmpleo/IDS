import psycopg2

class BDRequests():
    def __init__(self):
        self.conn = psycopg2.connect(database="SOV", user="postgres", password="1234", host="localhost", port="5432")

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