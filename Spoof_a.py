import email
from email import policy
import re
import extract_msg
from email.parser import BytesParser


def extract_domain(email_str):
    match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_str)
    return match.group(1) if match else None


def is_forwarded(msg, body):
    forward_indicators = []

    # 1. Check common forwarding headers
    forwarding_headers = [
        'X-Forwarded-For',
        'Resent-From',
        'Resent-To',
        'Resent-Date',
        'Resent-Message-ID',
        'X-MS-Exchange-Forwarding'
    ]

    for header in forwarding_headers:
        if header in msg:
            forward_indicators.append(f"Header found: {header}")

    # 2. Check for Outlook forwarding pattern
    outlook_pattern = r"De:\s.*?\nEnviado:\s.*?\nPara:\s.*?\nAsunto:"
    if body and re.search(outlook_pattern, body, re.IGNORECASE):
        forward_indicators.append("Outlook forwarding pattern detected")

    # 3. Check for common forwarding patterns
    forward_patterns = [
        (r"-----Original Message-----", "Original Message pattern"),
        (r"Begin forwarded message", "Begin forwarded message"),
        (r"--- Forwarded message ---", "Forwarded message pattern"),
        (r"De:\s.*?<mailto:.*?>", "De/mailto pattern"),
        (r"From:\s.*?\nSent:\s.*?\nTo:\s.*?\nSubject:", "From/Sent/To pattern")
    ]

    for pattern, description in forward_patterns:
        if body and re.search(pattern, body, re.IGNORECASE | re.DOTALL):
            forward_indicators.append(description)

    # 4. Check for Microsoft-specific forwarding indicators
    if 'X-MS-Exchange-Forwarding' in msg:
        forward_indicators.append("X-MS-Exchange-Forwarding header found")
    if 'X-MS-Has-Attach' in msg:
        forward_indicators.append("X-MS-Has-Attach header found")

    return bool(forward_indicators), forward_indicators


def get_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # Busca en todas las partes excepto adjuntos
            if "attachment" not in content_disposition:
                if content_type == "text/plain" or content_type == "text/html":
                    try:
                        body += part.get_content() + "\n"
                    except:
                        try:
                            body += part.get_payload(decode=True).decode(
                                errors='replace') + "\n"
                        except:
                            pass
    else:
        try:
            body = msg.get_content()
        except:
            try:
                body = msg.get_payload(decode=True).decode(errors='replace')
            except:
                pass

    return body if body.strip() else "NO CONTENT FOUND"


def analyze_email(file_path):
    is_msg = file_path.lower().endswith('.msg')
    body = ""
    headers = {}

    try:
        if is_msg:
            msg = extract_msg.Message(file_path)
            headers = {k: v for k, v in msg.header.items()}
            body = msg.body
        else:
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
                headers = dict(msg.items())
                body = get_email_body(msg)
    except Exception as e:
        return {"ERROR": f"Error al procesar el archivo: {str(e)}"}

    # ====== Forward Detection ======
    forwarded, forward_indicators = is_forwarded(headers, body)
    forwarded_warning = "YES (Forwarded Email)" if forwarded else "NO"

    # ====== Spoofing Detection ======
    from_email = headers.get('From', 'NO')
    return_path = headers.get('Return-Path', 'NO')
    spoofed = "NO"
    if from_email != 'NO' and return_path != 'NO':
        return_path_clean = re.sub(r'^<|>$', '', return_path)
        if from_email != return_path_clean:
            spoofed = f"YES (From: {from_email} ≠ Return-Path: {return_path_clean})"

    # ====== Source IPs ======
    ips_found = set()
    if 'X-Sender-IP' in headers:
        ips_found.add(headers['X-Sender-IP'])
    if 'Authentication-Results' in headers:
        spf_ip = re.search(r'sender IP is (\d+\.\d+\.\d+\.\d+)',
                           headers['Authentication-Results'])
        if spf_ip:
            ips_found.add(spf_ip.group(1))
    source_ips = " | ".join(ips_found) if ips_found else "NO"

    # ====== Results ======
    results = {
        "EVIDENCE": {
            "Valid Headers or Mail Sample": "YES",
            "Email Content": "YES" if body else "NO",
            "Is Forwarded?": forwarded_warning,
            "Forward Indicators": forward_indicators if forwarded else "None found"
        },
        "ANALYSIS RESULTS": {
            "Spoofed Email Account/Identity": spoofed,
            "Source IP": source_ips,
            "Source Email Account": from_email,
            "Source Domain": extract_domain(return_path) if return_path != 'NO' else "NO",
            "Relay Server": "NO",
            "Return-Path": return_path,
            "Reply-To": headers.get('Reply-To', 'NO'),
            "In-Reply-To": headers.get('In-Reply-To', 'NO'),
            "Associated Email Accounts": f"To: {headers.get('To', 'NO')} | Cc: {headers.get('Cc', 'NO')} | Bcc: {headers.get('Bcc', 'NO')}",
            "Authentication-Results": headers.get('Authentication-Results', 'NO'),
            "Message-ID": headers.get('Message-ID', 'NO'),
            "X-Empty-To": headers.get('X-Empty-To', 'NO'),
        }
    }
    return results


if __name__ == "__main__":
    # Cambia por tu archivo
    analysis = analyze_email(
        "archive/They will know..eml")
    print("=== EVIDENCE ===")
    for key, value in analysis["EVIDENCE"].items():
        print(f"{key}: {value}")

    print("\n=== ANALYSIS RESULTS ===")
    for key, value in analysis["ANALYSIS RESULTS"].items():
        print(f"{key}: {value}")
