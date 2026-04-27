import hashlib
import vt #pip install vt-py
import asyncio
import io
import os
from dotenv import load_dotenv

class VTScanner: # שיניתי את שם המחלקה כדי שלא יהיה זהה למתודה
    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv("VT_API_KEY")

    def run_scan(self, file_path): # המתודה הראשית (סינכרונית)
        try:
            # הוספת self. לפני שם המתודה
            return asyncio.run(self.check_file_vt_async(file_path))
        except Exception as e:
            return f"VT Error: {e}"

    async def check_file_vt_async(self, file_path):
        # שימוש ב-self כדי לקרוא למתודה אחרת במחלקה
        file_hash, clean_path = self.get_file_hash(file_path)

        if not file_hash:
            return "File hash error"

        if file_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
            return "The file is empty."

        async with vt.Client(self.api_key) as client:
            try:
                file_obj = await client.get_object_async(f"/files/{file_hash}")
                return file_obj.last_analysis_stats
            except vt.APIError as e:
                if e.code == "NotFoundError":
                    with open(clean_path, "rb") as f:
                        file_data = f.read()

                    file_memory_stream = io.BytesIO(file_data)
                    await client.scan_file_async(file_memory_stream, wait_for_completion=True)

                    file_obj = await client.get_object_async(f"/files/{file_hash}")
                    return file_obj.last_analysis_stats
                else:
                    return {"error": str(e)}

    def get_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        clean_path = file_path.strip().replace('"', '').replace("'", "")
        try:
            with open(clean_path, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest(), clean_path
        except FileNotFoundError:
            return None, None