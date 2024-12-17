Secure Backup and Encryption Management System
Overview
The Secure Backup and Encryption Management System is a Python-based application that provides comprehensive file management with advanced encryption and backup functionalities. It ensures data security, efficient organization, and easy accessibility through an intuitive graphical user interface (GUI). The system supports both AES (Advanced Encryption Standard) and RSA (Rivest-Shamir-Adleman) encryption algorithms, enabling robust protection for sensitive files.
Features
•	File Operations: Perform basic operations like renaming, reading, deleting, and restoring files.
•	Incremental Backup: Automatically create backups of selected files with version control for easy recovery.
•	Encryption and Decryption:
o	AES encryption for fast and secure file protection.
o	RSA encryption for advanced, public-private key-based security.
•	Disk Monitoring: View real-time capacity and usage of system drives (C: and D:).
•	GUI Integration: A user-friendly interface implemented using Tkinter to simplify navigation and operation.
•	Performance Comparison: Compare the encryption and decryption times of AES and RSA algorithms with graphical representation.
•	Version Restoration: Recover files to their previous states using stored backup versions.
•	Password Management: Securely store and verify passwords for encrypted files.
Requirements
•	Python 3.8 or higher
•	Required Python libraries:
o	tkinter (for GUI)
o	cryptography (for AES and RSA encryption)
o	matplotlib (for graphical representation)
o	psutil (for disk usage monitoring)
o	shutil (for file operations)
o	docx (for reading and writing .docx files)
Usage
Main Functionalities
1.	File Encryption:
o	Select a file and choose Encrypted File for AES or RSA Encrypt File for RSA encryption.
2.	File Decryption:
o	Select an encrypted file and choose Decrypted File for AES or RSA Decrypt File for RSA decryption.
3.	Incremental Backup:
o	Use the Backup File option to create versions of your files for restoration when needed.
4.	Performance Analysis:
o	Click on Compare AES vs RSA to view a graphical comparison of the encryption and decryption speeds.
5.	Disk Monitoring:
o	View the capacity and usage of your system drives in the Disk Space Information section.
Password Management
•	Passwords for AES-encrypted files are securely hashed and stored for verification.
•	RSA keys are managed and stored as .pem files for secure key handling.
Backup Restoration
•	Navigate to Restore File to retrieve older versions of your files.
Key Files
•	FileManagementSystem.py: Entry point of the application.
•	Encrypt.py: Contains AES encryption and decryption logic.
•	Encrypt_rsa.py: Implements RSA encryption and decryption methods.
•	requirements.txt: Lists all required libraries for the project.
Known Issues
•	RSA encryption may have limitations for files larger than the key size. Future updates will implement hybrid encryption for larger files.
Acknowledgments
Special thanks to Professor Dr. Rashid Sangi for their invaluable guidance and expertise in algorithm optimization and system design. The team's collective effort and collaboration were instrumental in delivering this project.
Contact
For further inquiries, please contact:
•	Team Lead: Sun Xubin(sunxub@kean.edu)
Zhong Zhuoqing (zhongzh@kean.edu)
QI Jiacheng(qiji@kean.edu)
