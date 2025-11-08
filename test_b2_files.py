from dotenv import load_dotenv
import os
from b2sdk.v2 import InMemoryAccountInfo, B2Api

load_dotenv()

info = InMemoryAccountInfo()
b2_api = B2Api(info)

b2_api.authorize_account(
    "production",
    os.environ.get('B2_APP_KEY_ID'),
    os.environ.get('B2_APP_KEY')
)

# Get your bucket
bucket_name = os.environ.get('B2_BUCKET_NAME')
bucket = b2_api.get_bucket_by_name(bucket_name)

print(f"Bucket Name: {bucket.name}")
print(f"Bucket Type: {bucket.type_}")  # Should be 'allPublic' or 'allPrivate'
print(f"Bucket ID: {bucket.id_}")

# List files
files = list(bucket.ls(recursive=True))
if files:
    print(f"\nFound {len(files)} files:")
    for file_version, folder_name in files:
        file_id = file_version.id_
        file_name = file_version.file_name
        download_url = b2_api.get_download_url_for_fileid(file_id)
        print(f"\n  File: {file_name}")
        print(f"  ID: {file_id}")
        print(f"  URL: {download_url}")
        print(f"  Test this URL in your browser!")
else:
    print("\nNo files in bucket yet")