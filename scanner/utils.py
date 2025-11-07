import io
import zipfile
from typing import Iterator, Tuple

TEXT_EXTS = {".py", ".txt", ".js", ".json", ".yml", ".yaml", ".env", ".html", ".md"}

def extract_zip_to_memory(data: bytes) -> Iterator[Tuple[str, bytes]]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if not info.is_dir():
                with zf.open(info) as f:
                    yield info.filename, f.read()

def is_text_path(path: str) -> bool:
    for ext in TEXT_EXTS:
        if path.lower().endswith(ext):
            return True
    return False
