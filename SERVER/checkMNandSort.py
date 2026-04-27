import sqlite3
import os


def verify_and_get_scan_type(file_path):
    # 1. חילוץ הסיומת המוצהרת
    _, claimed_ext = os.path.splitext(file_path)
    claimed_ext = claimed_ext.lower()

    # 2. קריאת החתימה האמיתית מהקובץ
    try:
        with open(file_path, 'rb') as f:
            actual_header = f.read(4)  # קורא את 4 הבייטים הראשונים
    except Exception as e:
        return f"Error reading file: {e}"

    conn = sqlite3.connect('signatures.db')
    cursor = conn.cursor()

    real_ext = "Unknown Binary"
    suggested_scan = "."

    # 3. בדיקה: האם החתימה תואמת לסיומת המוצהרת?
    cursor.execute('SELECT magic_bytes, scan_type FROM FileSignatures WHERE extension = ?', (claimed_ext,))
    row = cursor.fetchone()

    if row:
        expected_magic, scan_type = row
        if actual_header.startswith(expected_magic):
            conn.close()
            return {
                "status": "Authentic",
                "file_type": claimed_ext,
                "scan_to_perform": scan_type
            }

        # 4. תיקון: שולפים גם את magic_bytes כדי שנוכל להשוות באמת
        cursor.execute('SELECT extension, magic_bytes, scan_type FROM FileSignatures')
        all_signatures = cursor.fetchall()

        for ext, magic, s_type in all_signatures:  # מוסיפים s_type לשליפה
            if isinstance(magic, str):
                magic = magic.encode('latin-1')

            # בודק אם ה-Header שקראנו מהקובץ
            # מתאים לאחת מהחתימות שיש לנו ב-DB
            if actual_header.startswith(magic):
                real_ext = ext  # זו הסיומת האמיתית
                suggested_scan = s_type  # וזה סוג הסריקה שבאמת צריך להריץ
                break

    conn.close()

    return {
        "status": "SPOOFED_ATTEMPT",
        "claimed_type": claimed_ext,
        "actual_type": real_ext,
        "message": f"ALERT: File extension is spoofed! Claims to be {claimed_ext} but it is actually {real_ext}.",
        "scan_to_perform": suggested_scan
    }