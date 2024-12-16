# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import shutil
import sys
from pathlib import Path

root = Path(__file__).parent.parent.parent
src = root / "sigstore"
api_root = root / "docs" / "api"


def main(args: argparse.Namespace) -> None:
    """Main script."""
    if args.overwrite:
        shutil.rmtree(api_root, ignore_errors=True)
    elif not args.check and api_root.exists():
        print(f"API root {api_root} already exists, skipping.")
        sys.exit(0)

    seen = set()
    for path in src.rglob("*.py"):
        module_path = path.relative_to(src).with_suffix("")
        full_doc_path = api_root / path.relative_to(src).with_suffix(".md")

        # Exclude private entries
        if any(part.startswith("_") for part in module_path.parts):
            continue

        if args.check:
            if not full_doc_path.is_file():
                print(f"File {full_doc_path} does not exist.", file=sys.stderr)
                sys.exit(1)

        full_doc_path.parent.mkdir(parents=True, exist_ok=True)
        with full_doc_path.open("w") as f:
            f.write(f":::sigstore.{str(module_path).replace('/', '.')}\n ")

        seen.add(full_doc_path)

    # Add the root
    with (api_root / "index.md").open("w") as f:
        f.write("""!!! note

    The API reference is automatically generated from the docstrings

:::sigstore
        """)

    seen.add(api_root / "index.md")

    if args.check:
        if diff := set(api_root.rglob("*.md")).symmetric_difference(seen):
            print(f"Found leftover documentation file: {diff}", file=sys.stderr)
            sys.exit(1)
    else:
        print("API doc generated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate the structure for the API documentation."
    )
    parser.add_argument("--overwrite", action="store_true", default=False)
    parser.add_argument("--check", action="store_true", default=False)

    arguments = parser.parse_args()

    if arguments.check and arguments.overwrite:
        print("You can't specify both --check and --overwrite.", file=sys.stderr)
        sys.exit(1)

    main(arguments)
