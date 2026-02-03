from androguard.core.axml import AXMLPrinter
import xml.etree.ElementTree as ET
from lxml import etree

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

def exported_components(apk):
    manifest = apk.get_android_manifest_xml()

    if manifest is None:
        return {"error": "AndroidManifest.xml not found"}

    # ✅ CASE 1: Already parsed (lxml Element)
    if isinstance(manifest, etree._Element):
        root = manifest

    # ✅ CASE 2: Raw binary AXML (bytes)
    elif isinstance(manifest, (bytes, bytearray)):
        axml = AXMLPrinter(manifest)
        xml_bytes = axml.get_xml()
        root = ET.fromstring(xml_bytes)

    else:
        return {"error": f"Unknown manifest type: {type(manifest)}"}

    application = root.find("application")
    if application is None:
        return {"error": "<application> tag not found"}

    exported = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": []
    }

    components = {
        "activity": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers"
    }

    for tag, key in components.items():
        for comp in application.findall(tag):
            name = comp.get(ANDROID_NS + "name")
            exported_attr = comp.get(ANDROID_NS + "exported")

            if exported_attr == "true":
                exported[key].append(name)

    return exported
