# JS Lister

### **Created by: Vishal Suwalka**

JS Lister is a cybersecurity tool designed to identify and analyze JavaScript files for sensitive information such as API keys, tokens, and other configurations. This tool automates the discovery of JavaScript files from subdomains and uses regex-based patterns to extract critical data.  

---

## **Features**

- Automated subdomain discovery and JavaScript file retrieval.
- Regex-based sensitive data extraction.
- Log generation for analysis.
- Duplicate file elimination for efficiency.

---

## **Requirements**

- **Operating System**: Linux (tested on Kali Linux).  
- **Python Version**: 3.x or above.  
- **Dependencies**:  
  - Python libraries:  
    - `requests`  
    - `logging`  
    - `re`  
  - External tools:  
    - `waybackurls`  

---

## **Installation**

1. Clone the repository:
    ```bash
    git clone https://github.com/<username>/js-lister.git
    cd js-lister
    ```

2. Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Install `waybackurls` (required):
    ```bash
    go install github.com/tomnomnom/waybackurls@latest
    ```

4. Ensure `waybackurls` is in your PATH:
    ```bash
    export PATH=$PATH:~/go/bin
    source ~/.bashrc
    ```

---

## **Usage**

1. Prepare a list of subdomains in a file named `subdomains.txt`. Example:  
    ```plaintext
    example.com
    sub.example.com
    anotherdomain.com
    ```

2. Run the tool:
    ```bash
    python3 js_lister.py
    ```

3. Output:
   - Logs will be saved in `js_lister.log`.  
   - Sensitive data will be categorized and stored in `.txt` files (e.g., `sensitive_data_example_com.txt`).  

---

## **Regex Patterns**

The tool uses the following regex patterns to identify sensitive data:
- **JWT Tokens**: `eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+`  
- **AWS Access Key IDs**: `AKIA[0-9A-Z]{16}`  
- **API Keys**: `([A-Za-z0-9_-]{32,45})`  

For the full list of patterns, see the [Regex Patterns](#regex-patterns) section in the documentation.  

---

## **Contributing**

We welcome contributions! Feel free to open issues, submit pull requests, or suggest features.  

---

## **License**

This project is licensed under the MIT License. See `LICENSE` for details.  
