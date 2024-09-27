# Email-Fork
Email Fork is a lightweight Python tool designed to help you analyze .eml files. Emails can contain important information such as IP addresses, URLs, attachments, and authentication results that can reveal the legitimacy of the email or even possible spoofing attempts. Email Fork makes it easy to extract this information in a clear, organized way, so you can better understand the contents of an email.
#Features
IP Address Extraction: Finds all IP addresses within the email and provides details such as country and owner (ISP or organization).

URL Extraction: Identifies all URLs present in the email content.

Authentication Results: Extracts and analyzes SPF, DKIM, and DMARC authentication results to help determine if the email might be a spoofing attempt.

Attachment Information: Provides information about attachments in the email, such as the filename, file type, size, and a hash (SHA256).

Reply-To Address: Detects and displays the Reply-To address from the email headers, if present.
