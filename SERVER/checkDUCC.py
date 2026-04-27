import os
from oletools.olevba import VBA_Parser #pip install oletools


def checkPDForOFFICE(file_path, fileType):
    """
    Main entry point for file analysis.
    Detects file type and triggers the specific analysis engine.
    """
    file_extension = os.path.splitext(file_path)[1].lower()
    if fileType == '.pdf':
        return analyze_pdf(file_path)
    elif fileType in ['.doc', '.docx', '.xls', '.xlsm', '.docm']:
        return analyze_office(file_path)


def analyze_pdf(file_path):
    """
    Detailed PDF analysis for suspicious objects.
    """
    # Expanded list of suspicious PDF commands
    indicators = [
        b'/JavaScript', b'/JS',  # Scripting
        b'/OpenAction', b'/AA',  # Automatic triggers
        b'/EmbeddedFile',  # Hidden payloads
        b'/Launch',  # OS command execution
        b'/URI',  # External web links
        b'/AcroForm', b'/XFA'  # Dynamic forms (often used for exploits)
    ]

    found_risks = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            for ind in indicators:
                if ind in content:
                    found_risks.append(ind.decode())

        if found_risks:
            return f"PDF command/s found: {', '.join(found_risks)}"
        return "PDF seems clean (no active objects found)."
    except Exception as e:
        return f"PDF Analysis Error: {str(e)}"


def analyze_office(file_path):
    """
    Office document analysis using oletools.
    """
    try:
        vb_parser = VBA_Parser(file_path)
        if vb_parser.detect_macros():
            results = ["VBA Macros detected"]
            analysis = vb_parser.analyze_macros()
            for kw_type, keyword, description in analysis:
                if kw_type == 'Suspicious':
                    results.append(f"Found {keyword}: {description}.")
            return " ".join(results)
        return "No Macros detected in Office file."
    except Exception as e:
        return f"Office Analysis Error: {str(e)}"