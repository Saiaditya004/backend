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
from gradio_client import Client, handle_file

MANIFESTS_DIR = "manifests"
KEYS_DIR = "keys"
TRANSPARENCY_LOG = "transparency.log"

os.makedirs(MANIFESTS_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)
if not os.path.exists(TRANSPARENCY_LOG):
    open(TRANSPARENCY_LOG, "a").close()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load private key (for PoC). In prod use KMS/HSM.
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
    Detect if image is AI-generated using Gradio API
    Returns detection metadata including score, label, and model info
    """
    try:
        # Save image bytes to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_file:
            tmp_file.write(image_bytes)
            tmp_path = tmp_file.name
        
        try:
            # Call Gradio API
            client = Client("saiaditya004/AIvsREAL")
            result = client.predict(
                image=handle_file(tmp_path),
                api_name="/predict"
            )
            
            # Extract detection results
            label = result.get("label", "unknown")
            confidences = result.get("confidences", [])
            
            # Find the confidence score for the predicted label
            score = 0.0
            for conf in confidences:
                if conf.get("label") == label:
                    score = conf.get("confidence", 0.0)
                    break
            
            # Build detection result
            detection_result = {
                "model_id": "saiaditya004/AIvsREAL",
                "model_version": "v1",
                "model_hash": "gradio-api",
                "score": round(score, 4),
                "label": label,
                "all_confidences": confidences,
                "processed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            
            return detection_result
            
        finally:
            # Clean up temp file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    except Exception as e:
        raise Exception(f"AI detection failed: {str(e)}")

@app.route("/.well-known/public-key.pem", methods=["GET"])
def get_public_key():
    # Expose public key so verifiers can fetch and use it.
    return send_file(os.path.join(KEYS_DIR, "public_key.pem"), mimetype="application/x-pem-file")

@app.route("/api/sign-manifest", methods=["POST"])
def sign_manifest():
    """
    Expected JSON payload:
    {
      "image_hash": "sha256:abcd...",
      "capture": {...},
      "detection": {...},
      "uploader": {...}
    }
    """
    data = request.get_json()
    if not data or "image_hash" not in data:
        return jsonify({"error": "image_hash required"}), 400

    # Build canonical manifest structure
    manifest = {
        "asset": {"hash": data["image_hash"]},
        "capture": data.get("capture", {}),
        "detection": data.get("detection", {}),
        "uploader": data.get("uploader", None),
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": "v1"
    }

    # canonicalize and compute manifest hash (SHA-256 of sorted JSON)
    manifest_hash = sha256_hex_of_json(manifest)
    manifest_filename = f"{manifest_hash}.json"
    manifest_path = os.path.join(MANIFESTS_DIR, manifest_filename)

    # Sign the manifest bytes (canonical JSON)
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

    # Write signed manifest file (human-readable)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(signed_manifest, f, indent=2)

    # Append to a simple transparency log (manifest_hash and timestamp)
    with open(TRANSPARENCY_LOG, "a") as t:
        t.write(json.dumps({"manifest_hash": manifest_hash, "issued_at": signed_manifest["manifest"]["issued_at"]}) + "\n")

    manifest_url = request.url_root.rstrip("/") + f"/manifests/{manifest_hash}"
    return jsonify({
        "manifest_url": manifest_url,
        "manifest_hash": f"sha256:{manifest_hash}",
        "signed_manifest": signed_manifest,
        "timestamp": signed_manifest["manifest"]["issued_at"]
    }), 201

@app.route("/manifests/<manifest_hash>", methods=["GET"])
def fetch_manifest(manifest_hash):
    path = os.path.join(MANIFESTS_DIR, f"{manifest_hash}.json")
    if not os.path.exists(path):
        return jsonify({"error": "manifest not found"}), 404
    return send_file(path, mimetype="application/json")

@app.route("/api/verify-manifest", methods=["GET"])
def verify_manifest():
    """
    Query param: url or manifest_hash
    If manifest_url given, fetch internal file; if manifest_hash, use it.
    Returns: { ok, signature_valid, manifest, errors: [] }
    """
    manifest_url = request.args.get("url")
    manifest_hash = request.args.get("manifest_hash")
    if manifest_url:
        # for this PoC, manifest_url should point to our /manifests/<hash>
        # extract last path segment
        manifest_hash = manifest_url.rstrip("/").split("/")[-1]

    if not manifest_hash:
        return jsonify({"error": "url or manifest_hash required"}), 400

    path = os.path.join(MANIFESTS_DIR, f"{manifest_hash}.json")
    if not os.path.exists(path):
        return jsonify({"error": "manifest not found"}), 404

    signed_manifest = json.load(open(path, "r", encoding="utf-8"))
    manifest = signed_manifest.get("manifest")
    signature = signed_manifest.get("signature")
    if not manifest or not signature:
        return jsonify({"error": "invalid manifest format"}), 500

    # verify signature
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature_valid = verify_signature(manifest_bytes, signature)

    # simple trust determination (in PoC): if signature_valid -> server-signed
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
    """
    Accepts JSON:
    { "manifest_hash": "<hex>", "image_hash": "sha256:..." }
    Verifies that image_hash matches manifest.asset.hash and signature is valid.
    """
    data = request.get_json()
    if not data or "manifest_hash" not in data or "image_hash" not in data:
        return jsonify({"error": "manifest_hash and image_hash required"}), 400
    manifest_hash = data["manifest_hash"]
    image_hash = data["image_hash"]
    path = os.path.join(MANIFESTS_DIR, f"{manifest_hash}.json")
    if not os.path.exists(path):
        return jsonify({"error": "manifest not found"}), 404

    signed_manifest = json.load(open(path, "r", encoding="utf-8"))
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
    """
    Query param: image_hash (e.g., sha256:abc123...)
    Returns: { found: bool, manifest_hash?: string, manifest_url?: string }
    """
    image_hash = request.args.get("image_hash")
    if not image_hash:
        return jsonify({"error": "image_hash required"}), 400
    
    # Search through all manifest files for matching asset.hash
    for filename in os.listdir(MANIFESTS_DIR):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(MANIFESTS_DIR, filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                signed_manifest = json.load(f)
                manifest = signed_manifest.get("manifest", {})
                asset_hash = manifest.get("asset", {}).get("hash")
                
                if asset_hash == image_hash:
                    manifest_hash = filename.replace(".json", "")
                    manifest_url = request.url_root.rstrip("/") + f"/manifests/{manifest_hash}"
                    return jsonify({
                        "found": True,
                        "manifest_hash": manifest_hash,
                        "manifest_url": manifest_url,
                        "manifest": manifest
                    })
        except:
            continue
    
    return jsonify({"found": False})

@app.route("/api/detect-ai", methods=["POST"])
def detect_ai_endpoint():
    """
    AI Detection API Endpoint
    
    Expected JSON payload:
    {
      "image": "base64_encoded_image_string",
      "image_type": "jpeg" or "png" (optional, default: "jpeg")
    }
    
    Returns:
    {
      "success": true,
      "detection": {
        "model_id": "...",
        "model_version": "...",
        "model_hash": "...",
        "score": 0.XX,
        "label": "...",
        "processed_at": "2025-11-14T..."
      }
    }
    """
    try:
        data = request.get_json()
        
        if not data or "image" not in data:
            return jsonify({"success": False, "error": "image (base64) required"}), 400
        
        # Decode base64 image
        try:
            image_base64 = data["image"]
            image_bytes = base64.b64decode(image_base64)
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid base64 image: {str(e)}"}), 400
        
        # Validate image can be opened
        try:
            img = Image.open(io.BytesIO(image_bytes))
            img.verify()  # Verify it's a valid image
            # Reopen after verify (verify closes the file)
            image_bytes = base64.b64decode(image_base64)
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid image file: {str(e)}"}), 400
        
        # Run AI detection
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

SEALED_ITEMS_DIR = "sealed_items"
os.makedirs(SEALED_ITEMS_DIR, exist_ok=True)

@app.route("/api/sealed-items", methods=["GET"])
def list_sealed_items():
    """
    Query param: user_id (optional, for multi-user support)
    Returns: { items: [SealedImageItem[]] }
    """
    user_id = request.args.get("user_id", "default_user")
    user_file = os.path.join(SEALED_ITEMS_DIR, f"{user_id}.json")
    
    if not os.path.exists(user_file):
        return jsonify({"items": []})
    
    with open(user_file, "r", encoding="utf-8") as f:
        items = json.load(f)
    
    # Sort by sealed_at (newest first)
    items.sort(key=lambda x: x.get("sealed_at", ""), reverse=True)
    return jsonify({"items": items})

@app.route("/api/sealed-items", methods=["POST"])
def save_sealed_item():
    """
    Expected JSON payload:
    {
      "user_id": "optional",
      "item": {
        "imageUri": "...",
        "imageHash": "sha256:...",
        "manifest_url": "...",
        "manifest_hash": "sha256:...",
        "sealed_at": "2025-11-13T..."
      }
    }
    """
    data = request.get_json()
    if not data or "item" not in data:
        return jsonify({"error": "item required"}), 400
    
    user_id = data.get("user_id", "default_user")
    item = data["item"]
    
    # Validate required fields
    if not item.get("imageHash") or not item.get("manifest_url"):
        return jsonify({"error": "imageHash and manifest_url required"}), 400
    
    user_file = os.path.join(SEALED_ITEMS_DIR, f"{user_id}.json")
    
    # Load existing items
    items = []
    if os.path.exists(user_file):
        with open(user_file, "r", encoding="utf-8") as f:
            items = json.load(f)
    
    # Add timestamp if not present
    if "sealed_at" not in item:
        item["sealed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    # Deduplicate by imageHash (remove old entry if exists)
    items = [i for i in items if i.get("imageHash") != item["imageHash"]]
    items.insert(0, item)  # Add to front (newest first)
    
    # Save updated list
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)
    
    return jsonify({"success": True, "item": item}), 201

@app.route("/api/sealed-items/<image_hash>", methods=["DELETE"])
def delete_sealed_item(image_hash):
    """
    Delete a sealed item by imageHash
    Query param: user_id (optional)
    """
    user_id = request.args.get("user_id", "default_user")
    user_file = os.path.join(SEALED_ITEMS_DIR, f"{user_id}.json")
    
    if not os.path.exists(user_file):
        return jsonify({"error": "not found"}), 404
    
    with open(user_file, "r", encoding="utf-8") as f:
        items = json.load(f)
    
    # Find and remove item
    original_count = len(items)
    items = [i for i in items if i.get("imageHash") != image_hash]
    
    if len(items) == original_count:
        return jsonify({"error": "item not found"}), 404
    
    # Save updated list
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)
    
    return jsonify({"success": True, "deleted": image_hash})



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
