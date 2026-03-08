def detect_insecure_urls(strings):
    insecure = []
    for s in strings:
        if "http://" in s:
            insecure.append(s)
    return insecure
