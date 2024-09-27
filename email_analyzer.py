import re
import requests
import hashlib
from email import policy
from email.parser import BytesParser

class EmailAnalyzer:
    def __init__(self, email_content):
        self.email_content = email_content  # Store the email content
        self.results = {}

    # extract IP addresses and get country and ASN
    def extract_ips(self):
        ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ipv4_matches = re.findall(ipv4_pattern, self.email_content)
        
        # Remove redundant matches :{)
        unique_ips = set(ipv4_matches)

        ip_details = []
        for ip in unique_ips:
            try:
                details = self.get_ip_details(ip)
                ip_details.append(f"{ip} - Country: {details['country']}, Owner: {details['owner']}")
            except Exception as e:
                # Print or log the actual error for troubleshooting
                ip_details.append(f"{ip} - Could not retrieve details (Error: {str(e)})")
        
        self.results['IPs'] = ip_details
    
    def get_ip_details(self, ip):
        try:
            # ipinfo.io API (you can change it to your fav service provider)
            response = requests.get(f"http://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                data = response.json()
                return {
                    "country": data.get("country", "N/A"),
                    "owner": data.get("org", "N/A")  
                }
            else:
                raise Exception(f"API request failed with status code {response.status_code}")
        except Exception as e:
            raise Exception(f"Failed to retrieve IP details: {str(e)}")
            
    def extract_reply_to_address(self):
    
     reply_to_pattern = r'Reply-To:\s*(.*?)(?=\n\S|\Z)'  
     reply_to_matches = re.findall(reply_to_pattern, self.email_content, re.MULTILINE | re.IGNORECASE)
    
     if reply_to_matches:
         self.results['Reply-To'] = reply_to_matches[0].strip()  
     else:
         self.results['Reply-To'] = "No Reply-To address found"
		
        
    			
    def extract_urls(self):
        # Step 1: Handle URLs split across lines with '='
        email_content_fixed = re.sub(r'=\n', '', self.email_content)

        # Step 2: Regular expression for URL detection
        url_pattern = r'(https?://[^\s]+)'
        urls = re.findall(url_pattern, email_content_fixed)

        # Remove duplicates by converting the list to a set
        unique_urls = set(urls)

        self.results['URLs'] = list(unique_urls)

    def extract_authentication_results(self):
        # Extract the entire 'Authentication-Results' header
        auth_results = re.findall(r'(?i)Authentication-Results:[\s\S]+?(?=\n\S|\Z)', self.email_content)
        
        if auth_results:
            auth_header = " ".join(auth_results)  # Join the found results into a single string

            # Extract SPF result
            spf_match = re.search(r'spf=(pass|fail|neutral|none|softfail|temperror|permerror|timeout)', auth_header, re.IGNORECASE)
            spf_result = spf_match.group(1) if spf_match else "Could not find SPF result"
            
            # Extract DKIM result
            dkim_match = re.search(r'dkim=(pass|fail|neutral|none|softfail|temperror|permerror|timeout)', auth_header, re.IGNORECASE)
            dkim_result = dkim_match.group(1) if dkim_match else "Could not find DKIM result"
            
            # Extract DMARC result
            dmarc_match = re.search(r'dmarc=(pass|fail|neutral|none|softfail|temperror|permerror)', auth_header, re.IGNORECASE)
            dmarc_result = dmarc_match.group(1) if dmarc_match else "Could not find DMARC result"
        else:
            spf_result = "Could not find SPF result"
            dkim_result = "Could not find DKIM result"
            dmarc_result = "Could not find DMARC result"

        
        self.results['SPF'] = spf_result
        self.results['DKIM'] = dkim_result
        self.results['DMARC'] = dmarc_result

    #read EML file
    @staticmethod
    def read_eml(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()

    # Function to calculate the hash of the file content
    def calculate_file_hash(self, file_content, hash_type='sha256'):
        if hash_type == 'md5':
            hash_obj = hashlib.md5()
        else:
            hash_obj = hashlib.sha256()
        
        hash_obj.update(file_content)
        return hash_obj.hexdigest()

    # Function to extract attachments
    def extract_attachments(self):
        # Parse the email content
        email_message = BytesParser(policy=policy.default).parsebytes(self.email_content.encode('utf-8'))  # Convert to bytes
        
        attachments = []
        
        for part in email_message.iter_parts():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                file_content = part.get_payload(decode=True)
                size = len(file_content) if file_content else 0
                extension = filename.split('.')[-1] if filename else 'Unknown'
                file_hash = self.calculate_file_hash(file_content)  # Calculate SHA256 hash

                attachments.append({
                    'filename': filename,
                    'size': size,
                    'extension': extension,
                    'hash': file_hash  
                })
        
        self.results['Attachments'] = attachments

    # run all tools (default behavior)
    def run_all(self):
        self.extract_ips()
        self.extract_reply_to_address()
        self.extract_urls()
        self.extract_authentication_results()
        self.extract_attachments()

    # display results
    def display_results(self):
        for tool, result in self.results.items():
            print(f"{tool} found:")
            if isinstance(result, list):
                for item in result:
                    if isinstance(item, dict):
                        print(f"  - Filename: {item['filename']}, Size: {item['size']} bytes, Extension: {item['extension']}, Hash: {item['hash']}")
                    else:
                        print(f"  - {item}")
            else:
                print(f"  - {result}")
            print("\n")