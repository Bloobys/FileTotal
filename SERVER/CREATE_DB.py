import sqlite3


def setup_database():
    conn = sqlite3.connect('signatures.db')
    cursor = conn.cursor()

    # יצירת הטבלה
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS FileSignatures
                   (
                       extension
                       TEXT
                       PRIMARY
                       KEY,
                       magic_bytes
                       BLOB,
                       scan_type
                       TEXT
                   )
                   ''')

    # הכנסת נתונים בסיסיים (מיוצגים כ-Hex לטובת נוחות)
    signatures = [
        # --- קבצי PE (Portable Executable) ---
        # כולם מתחילים ב-'MZ' ונסרקים ע"י ה-PE Analyzer
        ('.exe', b'\x4d\x5a', 'checkPEfiles'),
        ('.dll', b'\x4d\x5a', 'checkPEfiles'),
        ('.sys', b'\x4d\x5a', 'checkPEfiles'),
        ('.scr', b'\x4d\x5a', 'checkPEfiles'),  # קבצי שומר מסך (נפוץ בוירוסים)
        ('.efi', b'\x4d\x5a', 'checkPEfiles'),
        ('.cpl', b'\x4d\x5a', 'checkPEfiles'),  # קבצי לוח הבקרה

        # --- קבצי PDF ---
        ('.pdf', b'\x25\x50\x44\x46', 'checkPDForOFFICE'),

        # --- קבצי Office מודרניים (Based on ZIP/XML) ---
        # כולם מתחילים ב-'PK' (חתימת ZIP)
        ('.docx', b'\x50\x4b\x03\x04', 'checkPDForOFFICE'),
        ('.xlsx', b'\x50\x4b\x03\x04', 'checkPDForOFFICE'),
        ('.pptx', b'\x50\x4b\x03\x04', 'checkPDForOFFICE'),
        ('.docm', b'\x50\x4b\x03\x04', 'checkPDForOFFICE'),  # אופיס עם מאקרו (חשוב!)
        ('.xlsm', b'\x50\x4b\x03\x04', 'checkPDForOFFICE'),
        ('.pptm', b'\x50\x4b\x03\x04', 'checkPDForOFFICE'),

        # --- קבצי Office ישנים (Binary format) ---
        # מתחילים ב-D0 CF 11 E0 (חתימת OLE)
        ('.doc', b'\xd0\xcf\x11\xe0', 'checkPDForOFFICE'),
        ('.xls', b'\xd0\xcf\x11\xe0', 'checkPDForOFFICE'),
        ('.ppt', b'\xd0\xcf\x11\xe0', 'checkPDForOFFICE'),]

    cursor.executemany('INSERT OR REPLACE INTO FileSignatures VALUES (?, ?, ?)', signatures)
    conn.commit()
    conn.close()


# הרצה פעם אחת להקמת ה-DB
setup_database()