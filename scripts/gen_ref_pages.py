from pathlib import Path

root = Path(__file__).parent.parent
src = root / "sigstore"

def main():
    for path in src.rglob("*.py"):
        module_path = path.relative_to(src).with_suffix("")
        doc_path = path.relative_to(src).with_suffix(".md")
        full_doc_path = root / "docs" / "API" / doc_path.with_suffix(".md")

        parts = tuple(module_path.parts)
        if any(part.startswith("_") for part in parts):
            continue

        full_doc_path.parent.mkdir(parents=True, exist_ok=True)
        with open(full_doc_path, "w") as f:
            f.write(f":::sigstore.{str(module_path).replace('/', '.')}\n ")

if __name__ == "__main__":
    main()