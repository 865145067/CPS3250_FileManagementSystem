import json
import shutil
import os
import time
from tkinter import messagebox

BACKUP_METADATA_FILE = "backup_metadata.json"
INCREMENTAL_BACKUP_FOLDER = "incremental_backups"  # Incremental backup directory

def load_backup_metadata():
    """Load backup metadata"""
    if os.path.exists(BACKUP_METADATA_FILE):
        with open(BACKUP_METADATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_backup_metadata(metadata):
    """Save the backup metadata"""
    with open(BACKUP_METADATA_FILE, "w") as file:
        json.dump(metadata, file, indent=4)

def incremental_backup(folder_path):
    """
    Perform incremental backup
:param folder_path: path of the folder to be backed up
    """
    if not os.path.exists(folder_path):
        print("The backup folder does not exist！")
        return


    metadata = load_backup_metadata()
    last_backup = metadata.get("last_backup", {})
    current_backup = {}

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_folder = os.path.join(INCREMENTAL_BACKUP_FOLDER, timestamp)
    os.makedirs(backup_folder, exist_ok=True)

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            modified_time = os.path.getmtime(file_path)
            relative_path = os.path.relpath(file_path, folder_path)

            if relative_path not in last_backup or last_backup[relative_path] < modified_time:
                dest_path = os.path.join(backup_folder, relative_path)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                shutil.copy2(file_path, dest_path)
                print(f"备份文件：{file_path}")

            current_backup[relative_path] = modified_time

    metadata["last_backup"] = current_backup
    metadata["last_backup_folder"] = backup_folder
    metadata["target_folder"] = folder_path
    save_backup_metadata(metadata)

    print(f"Incremental backup complete! Backup stored in：{backup_folder}")
def restore_backup(backup_folder, target_folder):
    """
    Restore the backup file to the target directory
:param backup_folder: path of the backup folder
:param target_folder: Recovery target directory path
    """
    if not os.path.exists(backup_folder):
        raise FileNotFoundError(f"The backup folder does not exist：{backup_folder}")

    if not os.path.exists(target_folder):
        os.makedirs(target_folder)

    # Traverse the backup folder and copy the files back to the destination directory
    for root, _, files in os.walk(backup_folder):
        for file_name in files:
            backup_file_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(backup_file_path, backup_folder)
            original_file_path = os.path.join(target_folder, relative_path)

            # Create destination folder
            os.makedirs(os.path.dirname(original_file_path), exist_ok=True)

            # Check for overwriting
            if os.path.exists(original_file_path):
                overwrite = messagebox.askyesno(
                    "File sharing conflict",
                    f"The destination file already exists：{original_file_path}\nif cover？"
                )
                if not overwrite:
                    continue


            shutil.copy2(backup_file_path, original_file_path)
            print(f"Restore Files：{original_file_path}")

    print(f"backup was restored to：{target_folder}")
def restore_last_backup():
    """
    Restore the last backup directly
    """
    metadata = load_backup_metadata()
    backup_folder = metadata.get("last_backup_folder")
    target_folder = metadata.get("target_folder")

    if not backup_folder or not os.path.exists(backup_folder):
        raise FileNotFoundError("No valid backup records found！")

    if not target_folder or not os.path.exists(target_folder):
        raise FileNotFoundError("backup destination folder does not exist！")

    for root, _, files in os.walk(backup_folder):
        for file_name in files:
            backup_file_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(backup_file_path, backup_folder)
            original_file_path = os.path.join(target_folder, relative_path)


            os.makedirs(os.path.dirname(original_file_path), exist_ok=True)


            shutil.copy2(backup_file_path, original_file_path)
            print(f"Restore Files：{original_file_path}")

    print(f"The backup was successfully restored to the target directory：{target_folder}")

