# FileTotal
========================================================================
תיאור הפרויקט:
מערכת FileTotal היא פתרון לסריקת קבצים המבוסס על ארכיטקטורת
לקוח-שרת. המערכת משלבת בדיקה מול VirusTotal, אימות Magic Number,
ניתוח סטטי של קבצים, וסיכום באמצעות בינה מלאכותית (Google Gemini)
כדי לענות למשתמש בשפה פשוטה: "האם הקובץ שלי בטוח לפתיחה?".


📁 מבנה הפרויקט:
SERVER.py         - שרת הליבה, מקבל קבצים ומפעיל את כל הסריקות.
CLIENT.py         - לקוח עם ממשק GUI לבחירת קובץ ושליחתו לשרת.
Caesar.py         - מחלקה להצפנת/פענוח Caesar Cipher.
checkVT.py        - מודול סריקה מול VirusTotal API.
checkMNandSort.py - אימות Magic Number וזיהוי קבצים מזויפים.
checkPEfiles.py   - ניתוח קבצי PE (EXE, DLL).
checkDUCC.py      - ניתוח קבצי PDF ו-Office.
CREATE_DB.py      - סקריפט יצירת מסד הנתונים (חד-פעמי).


🛠️ דרישות קדם ומערכת:
התקנת Python 3.9+ על שני המחשבים (לקוח ושרת).
התקנת ספריות: pip install -r requirements.txt
קובץ הגדרות: יש ליצור קובץ .env בתיקיית הפרויקט עם המפתחות:
VT_API_KEY=your_virustotal_api_key
GENAI_API_KEY=your_gemini_api_key
המפתחות חינמיים וניתנים להשגה ב:
VirusTotal:      https://www.virustotal.com
Google AI Studio: https://aistudio.google.com/app/apikey
רשת מקומית (LAN): השרת והלקוח חייבים להיות באותה רשת,
ופורט 5500 חייב להיות פתוח בחומת האש של השרת.
עדכון כתובת IP: בקובץ CLIENT.py יש לעדכן את self.server_ip
לכתובת ה-IP של מחשב השרת.


🚀 הוראות הפעלה:
יצירת מסד הנתונים (פעם אחת בלבד):
יש להריץ:  python CREATE_DB.py
הפעלת השרת (Server):
במחשב השרת, יש להריץ:  python SERVER.py
תופיע הודעה: [*] Server is listening on port 5500...
הפעלת הלקוח (Client):
במחשב הלקוח, יש להריץ:  python CLIENT.py
ייפתח חלון ה-GUI של FileTotal.
סריקת קובץ:
לחיצה על "Choose File" - לבחירת קובץ מהמחשב.
לחיצה על "Upload & Scan" - לשליחת הקובץ לסריקה.
המתנה לקבלת הדוח של Gemini במסך התוצאות.
