import requests
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import time
import xml.etree.ElementTree as ET
from datetime import datetime

# Paramètres SMTP --à modifier--
SMTP_SERVER = 'localhost'
SMTP_PORT = 25
SMTP_USERNAME = ''
SMTP_PASSWORD = ''
EMAIL_FROM = 'test1@gmail.com'
EMAIL_TO = 'test2@gmail.com'
EMAIL_SUBJECT = 'Veille MAJ sécurité - Patch Tuesday Microsoft'

# Identifiants de produit pour Windows Server 2008 R2 à 2022 regroupés par année
WINDOWS_SERVER_PRODUCT_IDS = {
    'Windows Server 2008 R2': ['10049', '10051'],
    'Windows Server 2008 SP2': ['10287'],
    'Windows Server 2012': ['10378', '10379'],
    'Windows Server 2012 R2': ['10483', '10543'],
    'Windows Server 2016': ['10816', '10855'],
    'Windows Server 2019': ['11571', '11572'],
    'Windows Server 2022': ['11923', '11924']
}

# Configuration du logger pour debug
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Fonction qui récupère les vulnérabilités en fonction du mois et année actuels à partir de l'api MSRC
def fetch_vulnerabilities():
    logging.debug("Fetching vulnerabilities from Microsoft API")
    
    # Obtenir le mois et l'année actuels
    now = datetime.now()
    month_year = now.strftime("%Y-%b")
    API_URL = f'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month_year}'
    
    try:
        response = requests.get(API_URL)
        response.raise_for_status()
        logging.debug(f"Response Status Code: {response.status_code}")
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Erreur lors de la récupération des vulnérabilités: {e}")
        return None

#Fonction qui classe le fichier XML(lien api MSRC) en différentes sections qui seront affichées dans le tableau 
def parse_vulnerabilities(xml_data):
    namespace = {'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1'} #utilisation d'un namespace
    vulnerabilities = []
    root = ET.fromstring(xml_data)
    #Récupération des cve 
    for vulnerability in root.findall(".//vuln:Vulnerability", namespace):
        cve = vulnerability.find("vuln:CVE", namespace).text if vulnerability.find("vuln:CVE", namespace) is not None else "N/A"
        title = vulnerability.find("vuln:Title", namespace).text if vulnerability.find("vuln:Title", namespace) is not None else "N/A"
        
        # Récupérer la description
        description_elements = vulnerability.findall("vuln:Notes/vuln:Note[@Type='FAQ']", namespace)
        description = " ".join([ET.tostring(e, method='text', encoding='unicode').strip() for e in description_elements])
        
        score = vulnerability.find("vuln:CVSSScoreSets/vuln:ScoreSet/vuln:BaseScore", namespace).text if vulnerability.find("vuln:CVSSScoreSets/vuln:ScoreSet/vuln:BaseScore", namespace) is not None else "N/A"
        exploitability = vulnerability.find("vuln:Threats/vuln:Threat/vuln:Exploitation", namespace).text if vulnerability.find("vuln:Threats/vuln:Threat/vuln:Exploitation", namespace) is not None else "N/A"
        impact = vulnerability.find("vuln:Threats/vuln:Threat/vuln:Impact", namespace).text if vulnerability.find("vuln:Threats/vuln:Threat/vuln:Impact", namespace) is not None else "N/A"
        link = f"https://msrc.microsoft.com/update-guide/en-US/vulnerability/{cve}"
        
        # Vérifier si au moins un produit affecté est un Windows Server
        affected_products = vulnerability.findall(".//vuln:ProductID", namespace)
        impacted_versions = set()
        for prod in affected_products:
            for year, products in WINDOWS_SERVER_PRODUCT_IDS.items():
                if prod.text in products:
                    impacted_versions.add(year)
        
        #si le produit correspond a un Windows server
        if impacted_versions:
            if score != "N/A" and float(score) >= 8.0:
                vulnerabilities.append({
                    'CVE': cve,
                    'Title': title,
                    'Description': description,
                    'CVSS': {'BaseScore': score},
                    'Link': link,
                    'Exploitation': exploitability,
                    'Impact': impact,
                    'Versions': ', '.join(impacted_versions)
                })
    return {'Vulnerability': vulnerabilities}

#Fonction qui crée le mail avec un tableau html
def create_email_content(vulnerabilities):
    logging.debug("Creating email content")
    content = """
    <html>
    <body>
    <h2>Voici les vulnérabilités du Patch Tuesday et leurs scores CVSS:</h2>
    <table border="1" style="border-collapse: collapse;">
        <tr>
            <th>CVE Titre</th>
            <th>CVE ID</th>
            <th>CVE Description</th>
            <th>Sévérité</th>
            <th>Score CVSS</th>
            <th>Lien vers la mise à jour</th>
            <th>Versions impactées</th>
        </tr>
    """
    for vuln in vulnerabilities.get('Vulnerability', []):
        content += f"""
        <tr>
            <td>{vuln.get('Title', 'N/A')}</td>
            <td>{vuln.get('CVE', 'N/A')}</td>
            <td>{vuln.get('Description', 'N/A')}</td>
            <td style="color: red;">Critique</td>
            <td>{vuln.get('CVSS', {}).get('BaseScore', 'N/A')}</td>
            <td><a href="{vuln.get('Link', 'N/A')}">Details</a></td>
            <td>{vuln.get('Versions', 'N/A')}</td>
        </tr>
        """
    content += """
    </table>
    </body>
    </html>
    """
    return content

#Fonction pour l'envoi du mail avec smtp
def send_email(content):
    logging.debug("Preparing to send email")
    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    msg['Subject'] = EMAIL_SUBJECT

    msg.attach(MIMEText(content, 'html'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        server.quit()
        logging.info("Email envoyé avec succès")
    except Exception as e:
        logging.error(f"Erreur lors de l'envoi de l'email: {e}")

def main():
    logging.debug("Main function start")
    xml_data = fetch_vulnerabilities()
    if xml_data:
        try:
            vulnerabilities = parse_vulnerabilities(xml_data)
            if vulnerabilities:
                content = create_email_content(vulnerabilities)
                send_email(content)
            else:
                logging.error("Impossible de parser les vulnérabilités")
        except Exception as e:
            logging.error(f"Une erreur inattendue s'est produite: {e}")
    else:
        logging.error("Impossible de récupérer les vulnérabilités")

    logging.debug("Waiting for 20 seconds before exiting due to error")
    input("Appuyez sur Entrée pour continuer...")  # Cette ligne permet de figer le shell

# Appel direct de la fonction principale pour tester immédiatement
main()
