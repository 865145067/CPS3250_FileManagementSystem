# **Secure Backup and Encryption Management System**

## **Overview**  
The **Secure Backup and Encryption Management System** is a Python-based application that integrates file management with advanced encryption and automatic backup functionalities. This system ensures **data security**, **efficient organization**, and **easy accessibility** through a user-friendly graphical interface built with Tkinter. The project leverages both **AES (Advanced Encryption Standard)** for symmetric encryption and **RSA (Rivest-Shamir-Adleman)** for asymmetric key-based security.

---

## **Features**  

### **1. File Operations**  
- Rename, read, delete, and restore files efficiently.
- Manage files with an intuitive interface that updates dynamically.

### **2. Incremental Backup**  
- Automatically create incremental backups of selected files.  
- Maintain version control for easy file restoration.

### **3. Encryption and Decryption**  
- **AES Encryption**: Fast and efficient encryption for large-scale files.  
- **RSA Encryption**: Secure encryption for sensitive files using public-private key pairs.  

   **Encryption Process**:  
   - **AES**: Encrypts file content using a 256-bit symmetric key.  
   - **RSA**: Encrypts the AES key for secure key exchange.  

   **Decryption Process**:  
   - **AES**: Decrypts file content using the symmetric AES key.  
   - **RSA**: Decrypts the AES key using the private RSA key.  

### **4. Disk Monitoring**  
- View real-time disk capacity and usage for system drives (C: and D:).  
- Provides progress bars and precise data for storage monitoring.  

### **5. GUI Integration**  
- Implemented using **Tkinter** for a clean and user-friendly graphical interface.  
- Simplifies file encryption, decryption, backup, and restoration processes.

### **6. Performance Comparison**  
- Compare AES and RSA encryption and decryption times.  
- Results are displayed graphically to highlight differences in speed and efficiency.  

### **7. Version Restoration**  
- Restore previous file versions using stored incremental backups.

### **8. Password Management**  
- Securely store and verify passwords for AES-encrypted files using hashing.  
- Manage RSA public and private keys saved as `.pem` files.

---

## **Requirements**

Ensure the following dependencies are installed to run the application:  

### **Python Version**  
- Python 3.8 or higher  

### **Dependencies**  
Install all required libraries using the following command:  
```bash
pip install -r requirements.txt
