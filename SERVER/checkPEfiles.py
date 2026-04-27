import pefile #pip install pefile


#לבקש מהמשתמש לעלות את הקובץ המקורי (.exe ולא .lnk וכו...)

def analyze_pe(file_path):
    try:
        # שימוש ב-with מבטיח סגירה אוטומטית של הקובץ
        with pefile.PE(file_path) as pe:
            results = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode()
                    results.append(f"Uses DLL: {dll_name}")

            for n, section in enumerate(pe.sections, 1):
                name = section.Name.decode().strip('\x00')
                entropy = section.get_entropy()
                results.append(f"Segment num.{n}: {name}, Entropy: {entropy:.2f}")

            return results
    except Exception as e:
        return f"PE Analysis ERROR: {e}"