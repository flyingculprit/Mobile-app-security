DANGEROUS_PERMISSIONS = [
    "READ_SMS", "SEND_SMS",
    "RECORD_AUDIO", "CAMERA",
    "READ_CONTACTS",
    "ACCESS_FINE_LOCATION",
    "WRITE_EXTERNAL_STORAGE"
]

def detect_dangerous_permissions(permissions):
    found = []
    for perm in permissions:
        for danger in DANGEROUS_PERMISSIONS:
            if danger in perm:
                found.append(perm)
    return found
