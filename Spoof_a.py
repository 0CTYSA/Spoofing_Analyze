import email
from email import policy
import re
import extract_msg


def extract_domain(email_str):
    match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_str)
    return match.group(1) if match else None


def analyze_email(file_path):
    is_msg = file_path.lower().endswith('.msg')

    if is_msg:
        try:
            msg = extract_msg.Message(file_path)
            headers = {**msg.header}
            body = msg.body
        except Exception as e:
            return {"ERROR": f"Error al leer el archivo .msg: {str(e)}"}
    else:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f, policy=policy.default)
            headers = dict(msg.items())
            body = msg.get_body()

    # ====== Detección de Reenvío ======
    forwarded_warning = ""
    if any(key.lower() in ['x-forwarded-for', 'forwarded'] for key in headers):
        forwarded_warning = "ADVERTENCIA: Este correo es un reenvío. Adjunte el mensaje original para un análisis preciso."

    # ====== Spoofing y Headers Adicionales ======
    from_email = headers.get('From', 'NO')
    return_path = headers.get('Return-Path', 'NO')
    reply_to = headers.get('Reply-To', 'NO')
    in_reply_to = headers.get('In-Reply-To', 'NO')  # Opcional

    spoofed = "NO"
    if from_email != 'NO' and return_path != 'NO':
        return_path_clean = re.sub(r'^<|>$', '', return_path)
        if from_email != return_path_clean:
            spoofed = f"YES (Spoofed: {from_email})"

    # ====== IPs y Dominios ======
    ips_found = set()
    if 'X-Sender-IP' in headers:
        ips_found.add(headers['X-Sender-IP'])
    if 'Authentication-Results' in headers:
        spf_ip = re.search(r'sender IP is (\d+\.\d+\.\d+\.\d+)',
                           headers['Authentication-Results'])
        if spf_ip:
            ips_found.add(spf_ip.group(1))
    source_ips = " | ".join(ips_found) if ips_found else "NO"

    # ====== Resultados ======
    results = {
        "EVIDENCE": {
            "Valid Headers or Mail Sample": "YES",
            "Email Content": "YES" if body else "NO",
            "Forwarded Warning": forwarded_warning if forwarded_warning else "NO"
        },
        "ANALYSIS RESULTS": {
            "Spoofed Email Account/Identity": spoofed,
            "Source IP": source_ips,
            "Source Email Account": from_email,
            "Source Domain": extract_domain(return_path) if return_path != 'NO' else "NO",
            "Relay Server": "NO",
            "Return-Path": return_path,
            "Reply-To": reply_to,
            "In-Reply-To": in_reply_to,  # Opcional
            "Associated Email Accounts": f"To: {headers.get('To', 'NO')} | Cc: {headers.get('Cc', 'NO')} | Bcc: {headers.get('Bcc', 'NO')}",
            "Authentication-Results": headers.get('Authentication-Results', 'NO'),
            "Message-ID": headers.get('Message-ID', 'NO'),
            "X-Empty-To": headers.get('X-Empty-To', 'NO'),
        }
    }
    return results


# Ejemplo de uso
if __name__ == "__main__":
    analysis = analyze_email("RV_ It’s too late to hide….msg")
    print("=== EVIDENCE ===")
    for key, value in analysis["EVIDENCE"].items():
        print(f"{key}: {value}")

    print("\n=== ANALYSIS RESULTS ===")
    for key, value in analysis["ANALYSIS RESULTS"].items():
        print(f"{key}: {value}")
