"""
Email Fetcher Module
Fetch emails from Gmail and Outlook using IMAP
"""

import imaplib
import email
from email.header import decode_header
import base64
from pathlib import Path
from typing import List, Dict, Optional
import re
from datetime import datetime


class EmailFetcher:
    """Fetch and parse emails from email providers"""
    
    # IMAP server configurations
    IMAP_SERVERS = {
        'gmail': {
            'host': 'imap.gmail.com',
            'port': 993
        },
        'outlook': {
            'host': 'outlook.office365.com',
            'port': 993
        },
        'yahoo': {
            'host': 'imap.mail.yahoo.com',
            'port': 993
        }
    }
    
    def __init__(self, email_address: str, password: str, provider: str = 'gmail'):
        """
        Initialize email fetcher
        
        Args:
            email_address: User's email address
            password: App-specific password (not regular password)
            provider: Email provider ('gmail', 'outlook', 'yahoo')
        """
        self.email_address = email_address
        self.password = password
        self.provider = provider.lower()
        self.mail = None
        
        if self.provider not in self.IMAP_SERVERS:
            raise ValueError(f"Provider '{provider}' not supported. Use: {list(self.IMAP_SERVERS.keys())}")
    
    def connect(self):
        """Connect to IMAP server"""
        try:
            server_config = self.IMAP_SERVERS[self.provider]
            self.mail = imaplib.IMAP4_SSL(server_config['host'], server_config['port'])
            self.mail.login(self.email_address, self.password)
            print(f"✓ Connected to {self.provider} IMAP server")
            return True
        except imaplib.IMAP4.error as e:
            print(f"✗ IMAP Login failed: {e}")
            print("\nNote: You need an 'App Password', not your regular password!")
            print("For Gmail: https://myaccount.google.com/apppasswords")
            print("For Outlook: https://account.live.com/proofs/AppPassword")
            return False
        except Exception as e:
            print(f"✗ Connection error: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from IMAP server"""
        if self.mail:
            try:
                self.mail.close()
                self.mail.logout()
                print("✓ Disconnected from IMAP server")
            except:
                pass
    
    def list_folders(self) -> List[str]:
        """List all available folders/labels"""
        if not self.mail:
            return []
        
        try:
            status, folders = self.mail.list()
            folder_names = []
            for folder in folders:
                folder_str = folder.decode()
                # Extract folder name from IMAP response
                match = re.search(r'"([^"]+)"$', folder_str)
                if match:
                    folder_names.append(match.group(1))
            return folder_names
        except Exception as e:
            print(f"Error listing folders: {e}")
            return []
    
    def select_folder(self, folder: str = 'INBOX'):
        """Select a folder to read from"""
        if not self.mail:
            return False
        
        try:
            status, messages = self.mail.select(folder)
            if status == 'OK':
                count = int(messages[0])
                print(f"✓ Selected folder '{folder}' with {count} messages")
                return True
            return False
        except Exception as e:
            print(f"Error selecting folder: {e}")
            return False
    
    def decode_text(self, text):
        """Decode email header text"""
        if text is None:
            return ""
        
        try:
            decoded_fragments = decode_header(text)
            decoded_text = ""
            for fragment, encoding in decoded_fragments:
                if isinstance(fragment, bytes):
                    try:
                        decoded_text += fragment.decode(encoding or 'utf-8', errors='ignore')
                    except:
                        decoded_text += fragment.decode('utf-8', errors='ignore')
                else:
                    decoded_text += str(fragment)
            return decoded_text
        except:
            return str(text)
    
    def get_email_body(self, msg) -> str:
        """Extract email body text"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                # Get text/plain or text/html
                if content_type == "text/plain":
                    try:
                        charset = part.get_content_charset() or 'utf-8'
                        body = part.get_payload(decode=True).decode(charset, errors='ignore')
                        break  # Prefer plain text
                    except:
                        pass
                elif content_type == "text/html" and not body:
                    try:
                        charset = part.get_content_charset() or 'utf-8'
                        html_body = part.get_payload(decode=True).decode(charset, errors='ignore')
                        # Strip HTML tags (basic)
                        body = re.sub('<[^<]+?>', '', html_body)
                    except:
                        pass
        else:
            try:
                charset = msg.get_content_charset() or 'utf-8'
                body = msg.get_payload(decode=True).decode(charset, errors='ignore')
            except:
                body = str(msg.get_payload())
        
        return body.strip()
    
    def get_attachments(self, msg) -> List[Dict]:
        """Extract attachments from email"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition"))
                
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        filename = self.decode_text(filename)
                        
                        # Get file data
                        file_data = part.get_payload(decode=True)
                        
                        attachments.append({
                            'filename': filename,
                            'size': len(file_data) if file_data else 0,
                            'content_type': part.get_content_type(),
                            'data': file_data
                        })
        
        return attachments
    
    def fetch_emails(self, max_emails: int = 10, search_criteria: str = 'ALL') -> List[Dict]:
        """
        Fetch emails from the selected folder
        
        Args:
            max_emails: Maximum number of emails to fetch
            search_criteria: IMAP search criteria (e.g., 'ALL', 'UNSEEN', 'FROM "example@email.com"')
        
        Returns:
            List of email dictionaries
        """
        if not self.mail:
            print("Not connected to IMAP server")
            return []
        
        emails = []
        
        try:
            # Search for emails
            status, message_ids = self.mail.search(None, search_criteria)
            
            if status != 'OK':
                print("No messages found")
                return []
            
            # Get list of message IDs
            message_id_list = message_ids[0].split()
            
            # Fetch latest emails first
            message_id_list = message_id_list[-max_emails:][::-1]
            
            print(f"Fetching {len(message_id_list)} emails...")
            
            for i, msg_id in enumerate(message_id_list, 1):
                try:
                    # Fetch the email
                    status, msg_data = self.mail.fetch(msg_id, '(RFC822)')
                    
                    if status != 'OK':
                        continue
                    
                    # Parse the email
                    raw_email = msg_data[0][1]
                    email_message = email.message_from_bytes(raw_email)
                    
                    # Extract email details
                    email_dict = {
                        'id': msg_id.decode(),
                        'subject': self.decode_text(email_message.get('Subject', '')),
                        'from': self.decode_text(email_message.get('From', '')),
                        'to': self.decode_text(email_message.get('To', '')),
                        'date': email_message.get('Date', ''),
                        'body': self.get_email_body(email_message),
                        'attachments': self.get_attachments(email_message),
                        'has_attachments': len(self.get_attachments(email_message)) > 0
                    }
                    
                    emails.append(email_dict)
                    print(f"  [{i}/{len(message_id_list)}] Fetched: {email_dict['subject'][:50]}")
                    
                except Exception as e:
                    print(f"  Error fetching email {msg_id}: {e}")
                    continue
            
            print(f"✓ Successfully fetched {len(emails)} emails")
            return emails
            
        except Exception as e:
            print(f"Error fetching emails: {e}")
            return []
    
    def save_attachment(self, attachment: Dict, output_dir: str = './downloads') -> Optional[Path]:
        """Save attachment to disk"""
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            file_path = output_path / attachment['filename']
            
            # Avoid overwriting files
            counter = 1
            while file_path.exists():
                stem = file_path.stem
                suffix = file_path.suffix
                file_path = output_path / f"{stem}_{counter}{suffix}"
                counter += 1
            
            with open(file_path, 'wb') as f:
                f.write(attachment['data'])
            
            print(f"✓ Saved attachment: {file_path}")
            return file_path
            
        except Exception as e:
            print(f"Error saving attachment: {e}")
            return None


def demo_gmail():
    """Demo: Fetch emails from Gmail"""
    print("="*80)
    print("GMAIL EMAIL FETCHER DEMO")
    print("="*80)
    print("\nNote: You need a Gmail App Password (not your regular password)")
    print("1. Go to: https://myaccount.google.com/apppasswords")
    print("2. Generate an app password")
    print("3. Use that password below\n")
    
    email_address = input("Enter your Gmail address: ").strip()
    app_password = input("Enter your App Password: ").strip()
    
    if not email_address or not app_password:
        print("Email and password are required!")
        return
    
    # Create fetcher
    fetcher = EmailFetcher(email_address, app_password, provider='gmail')
    
    # Connect
    if not fetcher.connect():
        return
    
    try:
        # List folders
        print("\nAvailable folders:")
        folders = fetcher.list_folders()
        for folder in folders[:10]:  # Show first 10
            print(f"  - {folder}")
        
        # Select inbox
        if fetcher.select_folder('INBOX'):
            # Fetch recent emails
            emails = fetcher.fetch_emails(max_emails=5, search_criteria='ALL')
            
            # Display results
            print("\n" + "="*80)
            print("FETCHED EMAILS")
            print("="*80)
            
            for i, email_data in enumerate(emails, 1):
                print(f"\n--- Email {i} ---")
                print(f"Subject: {email_data['subject']}")
                print(f"From: {email_data['from']}")
                print(f"Date: {email_data['date']}")
                print(f"Body Preview: {email_data['body'][:200]}...")
                print(f"Attachments: {len(email_data['attachments'])}")
                
                if email_data['attachments']:
                    print("  Attachment details:")
                    for att in email_data['attachments']:
                        print(f"    - {att['filename']} ({att['size']} bytes)")
    
    finally:
        fetcher.disconnect()


def demo_outlook():
    """Demo: Fetch emails from Outlook"""
    print("="*80)
    print("OUTLOOK EMAIL FETCHER DEMO")
    print("="*80)
    print("\nNote: You need an Outlook App Password")
    print("1. Go to: https://account.live.com/proofs/AppPassword")
    print("2. Generate an app password")
    print("3. Use that password below\n")
    
    email_address = input("Enter your Outlook/Hotmail address: ").strip()
    app_password = input("Enter your App Password: ").strip()
    
    if not email_address or not app_password:
        print("Email and password are required!")
        return
    
    # Create fetcher
    fetcher = EmailFetcher(email_address, app_password, provider='outlook')
    
    # Connect
    if not fetcher.connect():
        return
    
    try:
        # Select inbox
        if fetcher.select_folder('INBOX'):
            # Fetch recent emails
            emails = fetcher.fetch_emails(max_emails=5, search_criteria='ALL')
            
            # Display results
            print("\n" + "="*80)
            print("FETCHED EMAILS")
            print("="*80)
            
            for i, email_data in enumerate(emails, 1):
                print(f"\n--- Email {i} ---")
                print(f"Subject: {email_data['subject']}")
                print(f"From: {email_data['from']}")
                print(f"Date: {email_data['date']}")
                print(f"Body Preview: {email_data['body'][:200]}...")
                print(f"Attachments: {len(email_data['attachments'])}")
    
    finally:
        fetcher.disconnect()


if __name__ == "__main__":
    print("Email Fetcher Demo")
    print("\nChoose provider:")
    print("1. Gmail")
    print("2. Outlook/Hotmail")
    
    choice = input("\nEnter choice (1 or 2): ").strip()
    
    if choice == '1':
        demo_gmail()
    elif choice == '2':
        demo_outlook()
    else:
        print("Invalid choice!")
