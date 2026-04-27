import socket
import threading
import os
from google import genai #pip install -U google-genai

from checkDUCC import checkPDForOFFICE
from checkPEfiles import analyze_pe
from checkMNandSort import verify_and_get_scan_type
from checkVT import VTScanner
from Caesar import *
from dotenv import load_dotenv #pip install python-dotenv

ip = '10.252.1.172'
port = 5500

def scan(file_path):
    results = []
    vt_scanner = VTScanner()
    check = vt_scanner.run_scan(file_path)
    results.append(f"checkVT: {check}")
    check1 = verify_and_get_scan_type(file_path)
    results.append(f"checkMN: {check1}")
    if (check1['status'] == 'Authentic'):
        fileType = check1['file_type']
        scanType = check1['scan_to_perform']
    elif (check1['status'] == 'SPOOFED_ATTEMPT'):
        fileType = check1['actual_type']
        scanType = check1['scan_to_perform']
    if scanType == 'checkPDForOFFICE':
        check2 = checkPDForOFFICE(file_path, fileType)
    elif scanType == 'checkPEfiles':
        check2 = analyze_pe(file_path)
    results.append(f"SCAN: {check2}")
    return results

def handle_client(client_socket, address):
    key = 5
    xor = Caesar(key)
    save_path = ""  # נגדיר מראש כדי שנוכל לגשת לזה ב-finally
    try:
        # 1. קריאת ה-Header
        header_bytes = b""
        while True:
            char = client_socket.recv(1)
            if char == b'\n' or not char:
                break
            header_bytes += char

        if not header_bytes: return

        header = header_bytes.decode('utf-8')
        file_name, file_size = header.split('|')
        file_size = int(file_size)

        # 2. נתיב השמירה
        save_path = os.path.join("server_storage", file_name)

        # 3. קבלת תוכן הקובץ ושמירה לדיסק
        with open(save_path, "wb") as f:
            print(f"[*] Receiving {file_name} from {address}...")
            remaining = file_size
            while remaining > 0:
                chunk = client_socket.recv(min(remaining, 4096))
                if not chunk: break
                decrypted_chunk = xor.caesar_decipher_bytes(chunk, key)
                f.write(decrypted_chunk)
                remaining -= len(chunk)

        print("[*] Starting scan...")

        data = scan(save_path)
        prompt = f"""Role: You are a helpful Security Assistant. Your goal is to explain file scan results to a non-technical user in simple, everyday language. Avoid jargon.

Input Data: A list containing:

checkVT: VirusTotal stats.

checkMN: File type verification.

SCAN: Detailed internal scan (PE/PDF/Office).

Instructions for the Output: Please format the response exactly as follows:

Scan Results:
Based on the scan, this file is [SAFE / NOT SAFE / SUSPICIOUS] to open.

VirusTotal has found that this file is: [Simple summary, e.g., "Clean" or "Flagged as dangerous by some antivirus programs" and after Show what things the scan found and the number (don't show the type-unsupported and don't mention the things that 0 scans found)] ONLY USE THE INFORMATION FOR THIS LINE FORM THE "checkVT" AND SAY THE NUMBER OF SCAN RESULTS. 'undetected' MEANS ITS GOOD, IF IT SAYS 0 THAT MEANS THAT IT WAS NOT FOUND
Important VirusTotal Logic:
- 0 flagged = SAFE
- 1-2 flagged = SUSPICIOUS (could be false positive, recommend caution)
- 3+ flagged = NOT SAFE

The scan found that the file is: [State if it's "Authentic" or "A fake file type"].

Summary: Write a very short summary (2-3 sentences max). Focus only on the SCAN results. Explain what was found as if you are talking to a beginner. For example, instead of "JavaScript object", say "A hidden script that can run actions automatically". Tell the user if these findings are normal for this kind of file or if they are a "red flag". End with a clear recommendation.



Things found in the file: [List the findings from the SCAN result, show them with dots like: *   Uses X: (and explanation)] (in PEscan dont the show Segment and Entropy ONLY show which DLL it uses and explain what it does in one line) (if in the PDF/Office scans if there are commands or MACROS show them and explain in one line what they are doing).




Raw Data to Analyze:{data}"""
        response = c.models.generate_content(
            model="gemma-4-26b-a4b-it",
            contents=prompt)
        client_socket.send(response.text.encode('utf-8'))

    except Exception as e:
        errormsg = f"Error: {e}"
        errormsgsrv = f"[-] Error with {address}: {e}"
        print(errormsgsrv)
        try:
            if errormsg == "Error: cannot access local variable 'check2' where it is not associated with a value":
                msg = "Sorry! This type of File in not Supported Here"
                client_socket.send(msg.encode('utf-8'))
            else:
                client_socket.send(errormsg.encode('utf-8'))
        except:
            pass

    finally:
         #5. מחיקת הקובץ לאחר הסריקה
        if save_path and os.path.exists(save_path):
            try:
                os.remove(save_path)
                print(f"[X] Temporary file {save_path} deleted successfully.")
            except: pass
            client_socket.close()  # חשוב לסגור את הסוקט בסיום
            print (f"[-] Connection with {address} closed.")


def start_server():
    # יצירת תיקיית אחסון אם לא קיימת
    if not os.path.exists("server_storage"):
        os.makedirs("server_storage")

    Server_Socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    Server_Socket.bind((ip,port))
    Server_Socket.listen()
    print(" \n the Server is Listening....... ")
    while True:
        Client_socket, IP_PORT = Server_Socket.accept()
        print(f"\n The client with IP and PORT {IP_PORT} is Connected ")
        th_client = threading.Thread(target=handle_client, args=(Client_socket, IP_PORT))
        th_client.start()



if __name__ == "__main__":
    load_dotenv()
    api_key = os.getenv("GENAI_API_KEY")
    c = genai.Client(api_key=api_key)
    start_server()