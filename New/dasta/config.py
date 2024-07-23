import os

class Config:
    UPLOAD_FOLDER = 'static/uploads'
    DECOMPILE_FOLDER = 'static/decompiled'
    REPORT_FOLDER = 'static/reports'
    ALLOWED_EXTENSIONS = {'apk'}

    @staticmethod
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS
