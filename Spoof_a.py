import re
import os
import extract_msg
import tkinter as tk
from email import policy
from datetime import datetime
from email.parser import BytesParser
from tkinter import filedialog, messagebox


def select_input_file():
    """Abre ventana para seleccionar el archivo .eml o .msg"""
    root = tk.Tk()
    root.withdraw()
    return filedialog.askopenfilename(
        title="Seleccione el correo a analizar",
        filetypes=[("Archivos de correo", "*.eml *.msg")]
    )


def setup_reports_folder():
    """Crea la carpeta Reportes si no existe y devuelve su ruta"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(script_dir, "Reportes")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


def generate_report(analysis, original_path, reports_dir):
    """Genera el reporte (sobrescribe si existe)"""
    original_name = os.path.splitext(os.path.basename(original_path))[0]
    report_name = f"Reporte_{original_name}.txt"  # <-- Sin timestamp
    report_path = os.path.join(reports_dir, report_name)

    with open(report_path, 'w', encoding='utf-8') as f:
        # Encabezado con fecha/hora interna
        f.write(
            f"=== ÚLTIMO ANÁLISIS: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write(f"• Archivo: {os.path.basename(original_path)}\n")
        f.write(f"• Ruta completa: {original_path}\n\n")

        # Secciones
        for section, data in analysis.items():
            f.write(f"=== {section.upper()} ===\n")
            for key, value in data.items():
                if isinstance(value, list):
                    f.write(f"{key}: ")
                    for item in value:
                        # Une líneas en una sola
                        clean_item = " ".join(item.splitlines())
                        f.write(f"{clean_item}\n")
                else:
                    # Si no es lista, también normaliza
                    clean_value = " ".join(value.splitlines())
                    f.write(f"{key}: {clean_value}\n")
            f.write("\n")

    return report_path


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

    # ====== Source IPs and Domains ======
    ips_found = set()
    ip_domains = {}

    # 1. Extraer IPs de headers conocidos
    if 'X-Sender-IP' in headers:
        ips_found.add(headers['X-Sender-IP'])

    if 'Authentication-Results' in headers:
        spf_ip = re.search(r'sender IP is (\d+\.\d+\.\d+\.\d+)',
                           headers['Authentication-Results'])
        if spf_ip:
            ips_found.add(spf_ip.group(1))

    # 2. Analizar headers Received (solución para dict normal)
    received_headers = []
    if 'Received' in headers:
        # Si hay múltiples Received, los unimos (pueden venir como lista o str)
        if isinstance(headers['Received'], list):
            received_headers = headers['Received']
        else:
            received_headers = [headers['Received']]

    # Buscar también Received en mayúsculas/minúsculas alternativas
    for key in headers:
        if key.lower() == 'received' and key != 'Received':  # Si hay otra variante
            if isinstance(headers[key], list):
                received_headers.extend(headers[key])
            else:
                received_headers.append(headers[key])

    # Procesamiento de los Received
    for received in received_headers:
        # Busca patrones como "from dominio.com (IP)"
        matches = re.findall(
            r'from\s+([a-zA-Z0-9.-]+)\s+[\(\[](\d+\.\d+\.\d+\.\d+)[\)\]]',
            received
        )
        for domain, ip in matches:
            ips_found.add(ip)
            ip_domains[ip] = domain

    # Formatear resultado
    source_ips = []
    for ip in ips_found:
        if ip in ip_domains:
            source_ips.append(f"{ip} ({ip_domains[ip]})")
        else:
            source_ips.append(ip)

    source_ips_str = " | ".join(source_ips) if source_ips else "NO"

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
            "Source IP/Domain": source_ips,
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
    print("🔍 Analizador de Headers - v2.1 (Sobrescribe reportes)")

    # Configuración inicial
    reports_dir = setup_reports_folder()

    # Selección de archivo
    if input_file := select_input_file():
        try:
            # Análisis
            analysis = analyze_email(input_file)

            # Generación de reporte (sobrescribe)
            report_path = generate_report(analysis, input_file, reports_dir)

            # Resultado
            messagebox.showinfo(
                "✅ Análisis completado",
                f"Reporte actualizado en:\n{report_path}"
            )

            # Abrir carpeta (Windows/Mac/Linux)
            if os.name == 'nt':
                os.startfile(reports_dir)
            else:
                opener = 'open' if os.uname().sysname == 'Darwin' else 'xdg-open'
                os.system(f'{opener} "{reports_dir}"')

        except Exception as e:
            messagebox.showerror("❌ Error", f"Falló el análisis:\n{str(e)}")
    else:
        print("Operación cancelada")
