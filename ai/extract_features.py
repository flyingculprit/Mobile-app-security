import os
import re

def extract_features(decompiled_dir):
    # Initialize feature dictionary with all required features
    features = {
        'smali_files_count': 0,
        'hardcoded_keys_count': 0,
        'obfuscated_code_count': 0,
        'suspicious_network_count': 0,
        'permissions_count': 0,
        'exported_activities_count': 0,
        'imported_libraries_count': 0,
        'broadcast_receivers_count': 0,
        'services_count': 0,
        'content_providers_count': 0,
        'network_requests_count': 0,
        'hardcoded_urls_count': 0
    }

    # Count the number of .smali files
    smali_files_count = sum([len(files) for r, d, files in os.walk(decompiled_dir) if any(f.endswith('.smali') for f in files)])
    features['smali_files_count'] = smali_files_count

    # Check for hardcoded API keys or secrets
    hardcoded_keys_count = 0
    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(".xml") or file.endswith(".smali") or file.endswith(".java"):
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if "API_KEY" in content or "SECRET_KEY" in content:
                        hardcoded_keys_count += 1
    features['hardcoded_keys_count'] = hardcoded_keys_count

    # Check for obfuscated code in .smali files
    obfuscated_code_count = 0
    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(".smali"):
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if "goto" in content or "nop" in content or re.search(r'\bL[a-zA-Z0-9]{3,}\b', content):
                        obfuscated_code_count += 1
    features['obfuscated_code_count'] = obfuscated_code_count

    # Check for suspicious network activity
    suspicious_network_count = 0
    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(".xml") or file.endswith(".smali") or file.endswith(".java"):
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if "http://" in content or "https://" in content or re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content):
                        suspicious_network_count += 1
    features['suspicious_network_count'] = suspicious_network_count

    # Additional features (examples)
    # Update these parts based on your specific feature extraction needs
    # e.g., permissions_count, exported_activities_count, etc.

    # Example: Count permissions in AndroidManifest.xml
    manifest_path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    if os.path.exists(manifest_path):
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            features['permissions_count'] = sum(permission in content for permission in [
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_PHONE_STATE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.INTERNET"
            ])

    # Example: Count exported activities (this is a placeholder, adapt as needed)
    features['exported_activities_count'] = sum(
        "<activity android:exported=" in content for content in read_files_with_extensions(decompiled_dir, [".xml"])
    )

    # Ensure the feature order matches the model's training data
    feature_order = [
        'smali_files_count',
        'hardcoded_keys_count',
        'obfuscated_code_count',
        'suspicious_network_count',
        'permissions_count',
        'exported_activities_count',
        'imported_libraries_count',
        'broadcast_receivers_count',
        'services_count',
        'content_providers_count',
        'network_requests_count',
        'hardcoded_urls_count'
    ]

    # Construct feature vector
    feature_vector = [features.get(f, 0) for f in feature_order]

    return features, feature_vector

def read_files_with_extensions(directory, extensions):
    """Helper function to read files with specific extensions in a directory."""
    contents = []
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    contents.append(f.read())
    return contents
