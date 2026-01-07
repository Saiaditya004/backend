import os
import json
import hashlib
import time
import base64
import io
import tempfile
from flask import Flask, request, jsonify, send_file, abort
from flask_cors import CORS
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from PIL import Image
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import requests

HF_FASTAPI_URL = "https://saiaditya004-aivsreal-api.hf.space/predict"

load_dotenv()

# AWS S3 Configuration
S3_BUCKET = os.getenv("S3_BUCKET_NAME", "your-bucket-name")
S3_REGION = os.getenv("AWS_REGION", "us-east-1")
S3_MANIFESTS_PREFIX = "manifests/"
S3_SEALED_ITEMS_PREFIX = "sealed_items/"
S3_KEYS_PREFIX = "keys/"

s3_client = boto3.client("s3", region_name=S3_REGION)

# Local cache directories for keys
KEYS_DIR = "/tmp/keys"
LOCAL_MANIFESTS_CACHE = "/tmp/manifests_cache"
LOCAL_SEALED_CACHE = "/tmp/sealed_cache"

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(LOCAL_MANIFESTS_CACHE, exist_ok=True)
os.makedirs(LOCAL_SEALED_CACHE, exist_ok=True)

app = Flask(__name__)
CORS(app)

TRANSPARENCY_LOG = "transparency.log"

def download_from_s3(s3_key: str, local_path: str) -> bool:
    """Download file from S3 to local cache"""
    try:
        s3_client.download_file(S3_BUCKET, s3_key, local_path)
        return True
    except ClientError as e:
        print(f"Error downloading {s3_key}: {e}")
        return False

def upload_to_s3(local_path: str, s3_key: str) -> bool:
    """Upload file to S3"""
    try:
        s3_client.upload_file(local_path, S3_BUCKET, s3_key)
        return True
    except ClientError as e:
        print(f"Error uploading {s3_key}: {e}")
        return False

def get_from_s3(s3_key: str) -> dict:
    """Get JSON file from S3"""
    try:
        obj = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        return json.loads(obj["Body"].read().decode("utf-8"))
    except ClientError as e:
        print(f"Error getting {s3_key}: {e}")
        return None

def put_to_s3(s3_key: str, data: dict) -> bool:
    """Put JSON file to S3"""
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=json.dumps(data, indent=2).encode("utf-8"),
            ContentType="application/json"
        )
        return True
    except ClientError as e:
        print(f"Error putting {s3_key}: {e}")
        return False

def list_s3_keys(prefix: str) -> list:
    """List all keys in S3 with given prefix"""
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)
        if "Contents" not in response:
            return []
        return [obj["Key"] for obj in response["Contents"]]
    except ClientError as e:
        print(f"Error listing {prefix}: {e}")
        return []

# Initialize keys from S3 on startup
def init_keys():
    """Download keys from S3 or create new ones"""
    priv_key_s3 = S3_KEYS_PREFIX + "private_key.pem"
    pub_key_s3 = S3_KEYS_PREFIX + "public_key.pem"
    
    priv_key_local = os.path.join(KEYS_DIR, "private_key.pem")
    pub_key_local = os.path.join(KEYS_DIR, "public_key.pem")
    
    # Try to download from S3
    if download_from_s3(priv_key_s3, priv_key_local) and download_from_s3(pub_key_s3, pub_key_local):
        print("Keys loaded from S3")
        return
    
    # If not in S3, generate new keys and upload
    print("Generating new keys...")
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(priv_key_local, "wb") as f:
        f.write(priv_pem)
    with open(pub_key_local, "wb") as f:
        f.write(pub_pem)
    
    # Upload to S3
    upload_to_s3(priv_key_local, priv_key_s3)
    upload_to_s3(pub_key_local, pub_key_s3)
    print("Keys generated and uploaded to S3")

# Load keys
init_keys()

with open(os.path.join(KEYS_DIR, "private_key.pem"), "rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

with open(os.path.join(KEYS_DIR, "public_key.pem"), "rb") as f:
    PUBLIC_KEY_PEM = f.read()

def sha256_hex_of_json(obj):
    s = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(s).hexdigest()

def sign_bytes(data: bytes) -> str:
    sig = PRIVATE_KEY.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return sig.hex()

def verify_signature(manifest_bytes: bytes, signature_hex: str):
    pub = serialization.load_pem_public_key(PUBLIC_KEY_PEM)
    try:
        pub.verify(
            bytes.fromhex(signature_hex),
            manifest_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def detect_ai_generated(image_bytes: bytes) -> dict:
    """
    Detect if image is AI-generated using Hugging Face FastAPI Space
    """
    try:
        files = {
            "file": ("image.png", image_bytes, "image/png")
        }

        response = requests.post(
            HF_FASTAPI_URL,
            files=files,
            timeout=30
        )

        response.raise_for_status()
        result = response.json()

        return {
            "model_id": "saiaditya004/AIvsREAL",
            "model_version": "v1",
            "model_hash": "hf-fastapi-space",
            "label": result["label"],
            "score": round(result["score"], 4),
            "all_confidences": result["confidences"],
            "processed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    except requests.exceptions.RequestException as e:
        raise Exception(f"HF inference failed: {str(e)}")

@app.route("/.well-known/public-key.pem", methods=["GET"])
def get_public_key():
    return send_file(os.path.join(KEYS_DIR, "public_key.pem"), mimetype="application/x-pem-file")

@app.route("/api/sign-manifest", methods=["POST"])
def sign_manifest():
    """Sign manifest and store in S3"""
    data = request.get_json()
    if not data or "image_hash" not in data:
        return jsonify({"error": "image_hash required"}), 400

    manifest = {
        "asset": {"hash": data["image_hash"]},
        "capture": data.get("capture", {}),
        "detection": data.get("detection", {}),
        "uploader": data.get("uploader", None),
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": "v1"
    }

    manifest_hash = sha256_hex_of_json(manifest)
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature_hex = sign_bytes(manifest_bytes)

    signed_manifest = {
        "manifest": manifest,
        "signature": signature_hex,
        "signer": {
            "type": "poctest-rsa",
            "public_key_url": request.url_root.rstrip("/") + "/.well-known/public-key.pem"
        }
    }

    # Store in S3
    s3_key = S3_MANIFESTS_PREFIX + f"{manifest_hash}.json"
    if not put_to_s3(s3_key, signed_manifest):
        return jsonify({"error": "Failed to save manifest"}), 500

    manifest_url = request.url_root.rstrip("/") + f"/manifests/{manifest_hash}"
    return jsonify({
        "manifest_url": manifest_url,
        "manifest_hash": f"sha256:{manifest_hash}",
        "signed_manifest": signed_manifest,
        "timestamp": signed_manifest["manifest"]["issued_at"]
    }), 201

@app.route("/manifests/<manifest_hash>", methods=["GET"])
def fetch_manifest(manifest_hash):
    """Fetch manifest from S3"""
    s3_key = S3_MANIFESTS_PREFIX + f"{manifest_hash}.json"
    manifest_data = get_from_s3(s3_key)
    
    if not manifest_data:
        return jsonify({"error": "manifest not found"}), 404
    
    return jsonify(manifest_data)

@app.route("/api/verify-manifest", methods=["GET"])
def verify_manifest():
    """Verify manifest signature"""
    manifest_url = request.args.get("url")
    manifest_hash = request.args.get("manifest_hash")
    
    if manifest_url:
        manifest_hash = manifest_url.rstrip("/").split("/")[-1]

    if not manifest_hash:
        return jsonify({"error": "url or manifest_hash required"}), 400

    s3_key = S3_MANIFESTS_PREFIX + f"{manifest_hash}.json"
    signed_manifest = get_from_s3(s3_key)
    
    if not signed_manifest:
        return jsonify({"error": "manifest not found"}), 404

    manifest = signed_manifest.get("manifest")
    signature = signed_manifest.get("signature")
    
    if not manifest or not signature:
        return jsonify({"error": "invalid manifest format"}), 500

    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature_valid = verify_signature(manifest_bytes, signature)
    trust_level = "server-signed" if signature_valid else "invalid-signature"

    return jsonify({
        "ok": signature_valid,
        "signature_valid": signature_valid,
        "trust_level": trust_level,
        "manifest": manifest,
        "signer": signed_manifest.get("signer"),
        "errors": [] if signature_valid else ["signature did not verify"]
    })

@app.route("/api/verify-asset", methods=["POST"])
def verify_asset():
    """Verify asset against manifest"""
    data = request.get_json()
    if not data or "manifest_hash" not in data or "image_hash" not in data:
        return jsonify({"error": "manifest_hash and image_hash required"}), 400
    
    manifest_hash = data["manifest_hash"]
    image_hash = data["image_hash"]
    
    s3_key = S3_MANIFESTS_PREFIX + f"{manifest_hash}.json"
    signed_manifest = get_from_s3(s3_key)
    
    if not signed_manifest:
        return jsonify({"error": "manifest not found"}), 404

    manifest = signed_manifest.get("manifest")
    signature = signed_manifest.get("signature")
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature_valid = verify_signature(manifest_bytes, signature)

    asset_hash_in_manifest = manifest.get("asset", {}).get("hash")
    asset_match = (asset_hash_in_manifest == image_hash)
    ok = signature_valid and asset_match

    errors = []
    if not signature_valid:
        errors.append("signature invalid")
    if not asset_match:
        errors.append("asset hash mismatch")

    return jsonify({
        "ok": ok,
        "signature_valid": signature_valid,
        "asset_match": asset_match,
        "errors": errors
    })

@app.route("/api/lookup-by-hash", methods=["GET"])
def lookup_by_hash():
    """Lookup manifest by image hash"""
    image_hash = request.args.get("image_hash")
    if not image_hash:
        return jsonify({"error": "image_hash required"}), 400
    
    manifest_keys = list_s3_keys(S3_MANIFESTS_PREFIX)
    
    for s3_key in manifest_keys:
        signed_manifest = get_from_s3(s3_key)
        if not signed_manifest:
            continue
        
        manifest = signed_manifest.get("manifest", {})
        asset_hash = manifest.get("asset", {}).get("hash")
        
        if asset_hash == image_hash:
            manifest_hash = s3_key.replace(S3_MANIFESTS_PREFIX, "").replace(".json", "")
            manifest_url = request.url_root.rstrip("/") + f"/manifests/{manifest_hash}"
            return jsonify({
                "found": True,
                "manifest_hash": manifest_hash,
                "manifest_url": manifest_url,
                "manifest": manifest
            })
    
    return jsonify({"found": False})

@app.route("/api/detect-ai", methods=["POST"])
def detect_ai_endpoint():
    """AI Detection endpoint"""
    try:
        data = request.get_json()
        
        if not data or "image" not in data:
            return jsonify({"success": False, "error": "image (base64) required"}), 400
        
        try:
            image_base64 = data["image"]
            image_bytes = base64.b64decode(image_base64)
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid base64 image: {str(e)}"}), 400
        
        try:
            img = Image.open(io.BytesIO(image_bytes))
            img.verify()
            image_bytes = base64.b64decode(image_base64)
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid image file: {str(e)}"}), 400
        
        detection_result = detect_ai_generated(image_bytes)
        
        return jsonify({
            "success": True,
            "detection": detection_result
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/sealed-items", methods=["GET"])
def list_sealed_items():
    """List sealed items for user from S3"""
    user_id = request.args.get("user_id", "default_user")
    s3_key = S3_SEALED_ITEMS_PREFIX + f"{user_id}.json"
    
    items = get_from_s3(s3_key)
    if not items:
        return jsonify({"items": []})
    
    items.sort(key=lambda x: x.get("sealed_at", ""), reverse=True)
    return jsonify({"items": items})

@app.route("/api/sealed-items", methods=["POST"])
def save_sealed_item():
    """Save sealed item to S3"""
    data = request.get_json()
    if not data or "item" not in data:
        return jsonify({"error": "item required"}), 400
    
    user_id = data.get("user_id", "default_user")
    item = data["item"]
    
    if not item.get("imageHash") or not item.get("manifest_url"):
        return jsonify({"error": "imageHash and manifest_url required"}), 400
    
    s3_key = S3_SEALED_ITEMS_PREFIX + f"{user_id}.json"
    
    # Load existing items
    items = get_from_s3(s3_key)
    if not items:
        items = []
    
    if "sealed_at" not in item:
        item["sealed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    items = [i for i in items if i.get("imageHash") != item["imageHash"]]
    items.insert(0, item)
    
    if not put_to_s3(s3_key, items):
        return jsonify({"error": "Failed to save item"}), 500
    
    return jsonify({"success": True, "item": item}), 201

@app.route("/api/sealed-items/<image_hash>", methods=["DELETE"])
def delete_sealed_item(image_hash):
    """Delete sealed item from S3"""
    user_id = request.args.get("user_id", "default_user")
    s3_key = S3_SEALED_ITEMS_PREFIX + f"{user_id}.json"
    
    items = get_from_s3(s3_key)
    if not items:
        return jsonify({"error": "not found"}), 404
    
    original_count = len(items)
    items = [i for i in items if i.get("imageHash") != image_hash]
    
    if len(items) == original_count:
        return jsonify({"error": "item not found"}), 404
    
    if not put_to_s3(s3_key, items):
        return jsonify({"error": "Failed to delete item"}), 500
    
    return jsonify({"success": True, "deleted": image_hash})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)