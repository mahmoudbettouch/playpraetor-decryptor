import os
import gzip
import hashlib
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from io import BytesIO
import tempfile
import zipfile
from apkutils2 import APK
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sys

import axmlparserpy.axmlprinter as axmlprinter

def generate_key(package_name: str, version_name: str, str2: str) -> bytes:
    base = package_name + str2
    i = sum(ord(c) for c in base)
    
    md5_input = f"{package_name}{str2}{i}{version_name}".encode("utf-8")
    md5_hex = hashlib.md5(md5_input).hexdigest()
    
    offset = i % 5
    key_hex = md5_hex[offset : offset + 16]
    return key_hex.encode('utf-8')

def read_concatenated_assets(asset_dir: Path) -> bytes:
    buf = BytesIO()
    idx = 0
    while True:
        part = asset_dir / f"{idx:03d}"
        if not part.is_file():
            break
        buf.write(part.read_bytes())
        idx += 1
    
    if idx == 0:
        raise FileNotFoundError(f"No asset parts found in {asset_dir}")
    return buf.getvalue()

def decrypt_and_decompress(blob: bytes, key: bytes) -> bytes:
    """Decrypt AES-ECB and decompress GZIP"""
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(blob)
    decrypted = unpad(decrypted, AES.block_size)
    return gzip.decompress(decrypted)

def parse_manifest(manifest_path: str) -> tuple:
    """Parse AndroidManifest.xml and extract package info"""
    try:
        with open(manifest_path, 'rb') as f:
            ap = axmlprinter.AXMLPrinter(f.read())
        
        buff = minidom.parseString(ap.getBuff()).toxml()
        root = ET.fromstring(buff)
        android_ns = "{http://schemas.android.com/apk/res/android}"
        
        package_name = root.attrib.get("package")
        version_name = root.attrib.get(android_ns + "versionName")
        
        # Find appid
        appid = None
        for meta in root.iter("meta-data"):
            name = meta.attrib.get(android_ns + "name")
            if name == "appid":
                appid = meta.attrib.get(android_ns + "value")
                break
        
        return package_name, version_name, appid
    except Exception as e:
        print(f"Error parsing manifest: {e}")
        return None, None, None

def extract_package(asset_dir: str, package_name: str, version_name: str, 
                   str2_field: str, output_path: str = "output.bin"):

    asset_dir = Path(asset_dir)
    
    # Generate key
    key = generate_key(package_name, version_name, str2_field)
    print(f"Derived AES key (hex): {key.hex()}")
    
    # Read concatenated assets
    blob = read_concatenated_assets(asset_dir)
    print(f"Read {len(blob):,} bytes from {asset_dir}")
    
    # Decrypt and decompress
    result = decrypt_and_decompress(blob, key)
    print(f"Decompressed to {len(result):,} bytes")
    
    # Write output
    with open(output_path, "wb") as f:
        f.write(result)
    print(f"Written decrypted payload to {output_path}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <apk_file>")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    
    if not os.path.isfile(apk_path):
        print(f"Error: File {apk_path} not found")
        sys.exit(1)
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(apk_path, "r") as zf:
                manifest_path = None
                base_files = []
                
                # Extract files
                for zinfo in zf.infolist():
                    zinfo.flag_bits &= ~0x1  # clear encrypted flag
                    extracted_path = zf.extract(zinfo, path=temp_dir)
                    
                    if zinfo.filename == "AndroidManifest.xml":
                        manifest_path = extracted_path
                    elif zinfo.filename.startswith("assets/base/") and not zinfo.is_dir():
                        base_files.append(extracted_path)
            
            if not manifest_path:
                print("Error: AndroidManifest.xml not found")
                sys.exit(1)
            
            # Parse manifest
            package_name, version_name, appid = parse_manifest(manifest_path)
            
            if not all([package_name, version_name, appid]):
                print("Error: Could not extract required info from manifest")
                print(f"Package: {package_name}, Version: {version_name}, AppID: {appid}")
                sys.exit(1)
            
            print(f"Package name: {package_name}")
            print(f"Version name: {version_name}")
            print(f"App ID: {appid}")
            
            # Check if base assets exist
            base_dir = Path(temp_dir) / "assets" / "base"
            if not base_dir.exists():
                print("Error: assets/base/ directory not found")
                sys.exit(1)
            
            # Extract and decrypt
            output_name = f"{Path(apk_path).stem}-decrypted.apk"
            extract_package(
                asset_dir=str(base_dir),
                package_name=package_name,
                version_name=version_name,
                str2_field=appid,
                output_path=output_name
            )
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()