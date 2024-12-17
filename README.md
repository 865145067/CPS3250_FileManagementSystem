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
```

**Required Libraries**:  
- `tkinter`: For the graphical user interface.  
- `cryptography`: Provides AES and RSA encryption functionalities.  
- `matplotlib`: For performance comparison graphs.  
- `psutil`: For real-time disk space monitoring.  
- `shutil`: For file operations (backup, restore).  
- `docx`: For reading and writing `.docx` files.  

---

## **Usage**

### **1. Running the Application**  
To start the application, execute the following command in your terminal:  
```bash
python FileManagementSystem.py
```

### **2. Main Functionalities**

| **Functionality**         | **Description**                                                                 |
|---------------------------|-------------------------------------------------------------------------------|
| **File Encryption**       | Select a file and encrypt it using AES or RSA.                                |
| **File Decryption**       | Select an encrypted file and decrypt it back to its original form.            |
| **Incremental Backup**    | Automatically save versions of files for future recovery.                    |
| **Performance Analysis**  | Compare AES and RSA encryption/decryption times with visual graphs.           |
| **Disk Monitoring**       | Monitor real-time disk usage of system drives (C: and D:).                    |
| **Version Restoration**   | Restore a previous version of a file using stored backups.                   |

---

## **Project Structure**

The project directory includes the following key files:  

| **File Name**              | **Description**                                                               |
|----------------------------|-------------------------------------------------------------------------------|
| `FileManagementSystem.py`  | Main entry point of the application.                                          |
| `Encrypt.py`               | Contains AES encryption and decryption logic.                                |
| `Encrypt_rsa.py`           | Implements RSA encryption and decryption methods.                            |
| `requirements.txt`         | Lists all required libraries for the project.                                |
| `BackupManager.py`         | Manages incremental backup creation and restoration.                         |
| `PerformanceAnalyzer.py`   | Compares and analyzes AES and RSA performance and generates graphical output. |

---

## **Known Issues**

1. **RSA Encryption Limitations**:  
   - RSA cannot directly encrypt files larger than the RSA key size.  
   - In the current version, only small files or keys can be encrypted using RSA.  
   - **Solution**: Hybrid encryption using AES for file encryption and RSA for key encryption is implemented to handle larger files efficiently.  

2. **Performance Delays**:  
   - Larger files may take longer to process during encryption or decryption.  

**Planned Updates**:  
- Further optimize encryption for larger files using hybrid methods.  
- Add support for more file types.

---

## **Performance Analysis**

The project compares the encryption and decryption times of AES and RSA algorithms.  

### **Results Summary**:  
- **AES**:  
   - Faster encryption and decryption, suitable for bulk data.  
- **RSA**:  
   - Slower for large files, but highly secure and effective for key exchange.  

### **Graphical Representation**:  
Results are displayed as graphs to clearly illustrate the differences in performance.

---

## **Acknowledgments**

We extend our gratitude to **Professor Dr. Rashid Sangi** for providing valuable insights and guidance throughout the development of this project.  

---

## **Contact**

For any inquiries or feedback, feel free to reach out to us:  

- **Team Lead**:  
   - Sun Xubin ([sunxub@kean.edu](mailto:sunxub@kean.edu))  

- **Team Members**:  
   - Zhong Zhuoqing ([zhongzh@kean.edu](mailto:zhongzh@kean.edu))  
   - Qi Jiacheng ([qiji@kean.edu](mailto:qiji@kean.edu))  

---

## **License**

This project is licensed under the **MIT License**. For details, see the [LICENSE](./LICENSE) file in the repository.

**Thank you for using the Secure Backup and Encryption Management System! 🚀**  
Feel free to fork, contribute, and report any issues you encounter.  
```

---
