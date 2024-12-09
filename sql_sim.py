import sqlite3
from colorama import init, Fore
import time

# Initialize colorama for colored output
init()

def create_database():
    conn = sqlite3.connect(':memory:')  # Create database in memory
    cursor = conn.cursor()
    
    # Create a sample users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    ''')
    
    # Insert sample data
    sample_data = [
        (1, 'admin', 'admin123'),
        (2, 'user1', 'pass123'),
        (3, 'user2', 'password123')
    ]
    cursor.executemany('INSERT INTO users VALUES (?,?,?)', sample_data)
    conn.commit()
    return conn

def vulnerable_login(username, password):
    # This is intentionally vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(Fore.YELLOW + "\n[*] Executing query: " + query + Fore.RESET)
    
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except sqlite3.Error as e:
        print(Fore.RED + f"[!] SQL Error: {e}" + Fore.RESET)
        return None

def secure_login(username, password):
    # This is the secure way using parameterized queries
    query = "SELECT * FROM users WHERE username=? AND password=?"
    print(Fore.YELLOW + "\n[*] Executing secure query with parameters" + Fore.RESET)
    
    try:
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        result = cursor.fetchall()
        return result
    except sqlite3.Error as e:
        print(Fore.RED + f"[!] SQL Error: {e}" + Fore.RESET)
        return None

def main():
    print(Fore.GREEN + """
    SQL Injection Simulator
    ----------------------
    Educational purposes only!
    """ + Fore.RESET)
    
    while True:
        print("\n1. Test vulnerable login")
        print("2. Test secure login")
        print("3. Exit")
        
        choice = input("\nSelect option: ")
        
        if choice == '3':
            break
            
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        if choice == '1':
            print(Fore.CYAN + "\n[*] Testing vulnerable login..." + Fore.RESET)
            result = vulnerable_login(username, password)
        elif choice == '2':
            print(Fore.CYAN + "\n[*] Testing secure login..." + Fore.RESET)
            result = secure_login(username, password)
        else:
            print(Fore.RED + "[!] Invalid option" + Fore.RESET)
            continue
            
        if result:
            print(Fore.GREEN + f"\n[+] Login successful! Found {len(result)} records:" + Fore.RESET)
            for row in result:
                print(f"ID: {row[0]}, Username: {row[1]}, Password: {row[2]}")
        else:
            print(Fore.RED + "\n[-] Login failed!" + Fore.RESET)

if __name__ == "__main__":
    conn = create_database()
    try:
        main()
    finally:
        conn.close()