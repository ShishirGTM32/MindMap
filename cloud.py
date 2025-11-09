import os
import magic
from b2sdk.v2 import InMemoryAccountInfo, B2Api
from werkzeug.utils import secure_filename
from datetime import datetime

info = InMemoryAccountInfo()
b2_api = B2Api(info)

try:
    b2_api.authorize_account(
        "production",
        os.environ.get('B2_APP_KEY_ID'),
        os.environ.get('B2_APP_KEY')
    )
    print("✓ Backblaze B2 connected successfully")
except Exception as e:
    print(f"✗ B2 Authorization failed: {e}")

B2_BUCKET_NAME = os.environ.get('B2_BUCKET_NAME')

class B2FileManager:
    
    ALLOWED_MIME_TYPES = {
        'application/pdf',
        'image/png', 'image/jpeg', 'image/gif',
        'text/plain', 'text/csv',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/zip'
    }
    
    MAX_FILE_SIZE = 16 * 1024 * 1024
    
    @staticmethod
    def validate_and_upload(file, user_id):
        if not file or not file.filename:
            return False, "No file provided", None
        
        safe_filename = secure_filename(file.filename)
        if not safe_filename or '.' not in safe_filename:
            return False, "Invalid filename", None
        
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > B2FileManager.MAX_FILE_SIZE:
            return False, f"File too large (max 16MB)", None
        
        if file_size == 0:
            return False, "File is empty", None
        
        file.seek(0)
        file_bytes = file.read(2048)
        file.seek(0)
        
        try:
            detected_mime = magic.from_buffer(file_bytes, mime=True)
        except:
            return False, "Could not detect file type", None
        
        if detected_mime not in B2FileManager.ALLOWED_MIME_TYPES:
            return False, f"File type not allowed: {detected_mime}", None
        
        try:
            bucket = b2_api.get_bucket_by_name(B2_BUCKET_NAME)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"user_{user_id}/{timestamp}_{safe_filename}"
            
            file.seek(0)
            file_content = file.read()
            
            # Changed: Use 'attachment' to force download instead of 'inline'
            file_info = bucket.upload_bytes(
                data_bytes=file_content,
                file_name=unique_filename,
                content_type=detected_mime,
                file_infos={
                    'b2-content-disposition': f'attachment; filename="{safe_filename}"'
                }
            )
            
            download_url = b2_api.account_info.get_download_url()
            base_url = f"{download_url}/file/{B2_BUCKET_NAME}/{unique_filename}"
            
            file_data = {
                'b2_file_id': file_info.id_,
                'b2_file_name': unique_filename,
                'download_url': base_url,
                'original_filename': safe_filename,
                'file_size': file_size,
                'mime_type': detected_mime
            }
            
            print(f"✓ File uploaded: {unique_filename}")
            print(f"  File ID: {file_info.id_}")
            print(f"  Base URL: {base_url}")
            
            return True, "File uploaded successfully", file_data
            
        except Exception as e:
            print(f"B2 Upload error: {e}")
            return False, f"Upload failed: {str(e)}", None
    

    @staticmethod
    def get_download_authorization(b2_file_name, duration_seconds=3600, force_download=True):
        """
        Generate download authorization with optional forced download
        
        Args:
            b2_file_name: Name of file in B2
            duration_seconds: How long the authorization is valid
            force_download: If True, adds Content-Disposition header to force download
        """
        try:
            bucket = b2_api.get_bucket_by_name(B2_BUCKET_NAME)
            
            # Extract original filename from the path
            original_name = b2_file_name.split('/')[-1]
            # Remove timestamp prefix (e.g., "20250108_123456_")
            if '_' in original_name:
                parts = original_name.split('_', 2)
                if len(parts) == 3:
                    original_name = parts[2]
            
            # For forced download, set content disposition in file_info
            if force_download:
                auth_token = bucket.get_download_authorization(
                    file_name_prefix=b2_file_name,
                    valid_duration_in_seconds=duration_seconds,
                    b2_content_disposition=f'attachment; filename="{original_name}"'
                )
            else:
                auth_token = bucket.get_download_authorization(
                    file_name_prefix=b2_file_name,
                    valid_duration_in_seconds=duration_seconds
                )
            
            download_url = b2_api.account_info.get_download_url()
            file_url = f"{download_url}/file/{B2_BUCKET_NAME}/{b2_file_name}"
            
            print(f"✓ Generated download authorization for: {b2_file_name}")
            print(f"  Token valid for: {duration_seconds} seconds")
            print(f"  Force download: {force_download}")
            print(f"  Original filename: {original_name}")
            
            return {
                'url': file_url,
                'authorization_token': auth_token,
                'expires_in': duration_seconds
            }
            
        except Exception as e:
            print(f"Error generating download authorization: {e}")
            return None
    
    @staticmethod
    def download_file_content(b2_file_name):
        """
        Download file content from B2 using SDK
        Returns: (success, content_bytes, error_message)
        """
        try:
            bucket = b2_api.get_bucket_by_name(B2_BUCKET_NAME)
            
            # Download file using B2 SDK
            downloaded_file = bucket.download_file_by_name(b2_file_name)
            
            # Get content as bytes
            from io import BytesIO
            buffer = BytesIO()
            downloaded_file.save(buffer)
            content = buffer.getvalue()
            
            print(f"✓ Downloaded {len(content)} bytes from B2: {b2_file_name}")
            return True, content, None
            
        except Exception as e:
            print(f"✗ Error downloading file from B2: {e}")
            return False, None, str(e)
    
    @staticmethod
    def delete_file(b2_file_id, b2_file_name):
        try:
            b2_api.delete_file_version(b2_file_id, b2_file_name)
            
            print(f"✓ File deleted from B2: {b2_file_name} (ID: {b2_file_id})")
            return True
            
        except Exception as e:
            print(f"✗ B2 Delete error: {e}")
            return False