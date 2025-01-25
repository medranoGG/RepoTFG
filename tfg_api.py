import re
import whois
import base64
import requests
import numpy as np
import pandas as pd
from bs4 import BeautifulSoup
from datetime import datetime
from tldextract import extract
from googlesearch import search
from tfg_code import principal_program
from flask import Flask, request, jsonify

#####################################
# Funciones de la API, en total 30: #
# -1 -> Phishing                    #
#  0 -> Sospechoso                  #
#  1 -> Legítimo                    #
#####################################

def having_ip_address(url):
    # -1 -> Si la URL contiene una IP
    #  1 -> Si la URL no contiene una IP
    try:
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

        if re.search(ip_pattern, url):
            return -1
        else:
            return 1

    except:
        return -1


def url_length(url):
    # -1 -> Si la longitud es mayor que X
    #  0 -> Si la longitu está entre 54 y 75
    #  1 -> Si la longitud es menor que X
    try:
        length=len(url)

        if(length < 54):
            return 1
        elif(54 <= length <= 75):
            return 0
        else:
            return -1

    except:
        return -1


def shortining_service(url):
    # -1 -> Si la URL usa servicios de acortamiento
    #  1 -> Si la URL no usa servicios de acortamiento
    try:
        shortening_services = [
            "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd",
            "buff.ly", "adf.ly", "bit.do", "shorte.st", "mcaf.ee",
            "soo.gd", "yourls.org", "rebrandly.com", "clickmeter.com",
            "tiny.cc", "cutt.ly", "v.gd", "qr.ae", "bl.ink", "short.io"
        ]
        domain = f"{extract(url).domain}.{extract(url).suffix}"

        if domain in shortening_services:
            return -1
        else:
            return 1

    except:
        return -1


def having_at_symbol(url):
    # -1 -> Si la URL contiene un "@"
    #  1 -> Si la URL no contiene un "@"
    try:
        if "@" in url:
            return -1
        else:
            return 1

    except:
        return -1


def double_slash_redirecting(url):
    # -1 -> Si la posición de "//" en la URL es mayor o igual a 7
    #  1 -> Si la posición de "//" en la URL es menor a 7
    try:
        if url.rfind('//') >= 7:
            return -1
        else:
            return 1

    except:
        return -1


def prefix_suffix(url):
    # -1 -> Si el dominio contiene un "@"
    #  1 -> Si el dominio no contiene un "@"
    try:
        domain = f"{extract(url).domain}.{extract(url).suffix}"
        if "-" in domain:
            return -1
        else:
            return 1

    except:
        return -1


def having_sub_domain(url):
    # -1 -> Tiene más de un subdominio
    #  0 -> Tiene un subdominio
    #  1 -> No tiene subdominio
    try:
        subdomain = extract(url).subdomain

        if subdomain.count('.') > 0:
            return -1
        elif subdomain:
            return 0
        else:
            return 1

    except:
        return -1


def sslfinal_state(url):
    # -1 -> El sitio no usa HTTPS
    #  1 -> El sitio usa HTTPS
    try:
        pattern = r'^https://'

        if re.match(pattern, url):
            return 1
        else:
            return -1

    except:
        return -1


def domain_registration_length(url):
    # -1 -> Si el dominio expira en menos de un año
    #  1 -> Si el dominio expira en más de un año
    try:
        w = whois.whois(url)
        expiration_date = w.expiration_date

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        expiration_date = datetime.strptime(str(expiration_date), "%Y-%m-%d %H:%M:%S")
        current_date = datetime.now()
        delta = (expiration_date - current_date).days

        if delta <= 365:
            return -1
        else:
            return 1

    except:
        return -1


def favicon(url):
    # -1 -> Si el favicon se carga desde un dominio distinto al que se muestra en la barra de direcciones
    #  1 -> Si el favicon se carga desde el mismo dominio al que se muestra en la barra de direcciones
    try:
        base_domain = f"{extract(url).domain}.{extract(url).suffix}"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        for head in soup.find_all('head'):
            for link in head.find_all('link', href=True):
                favicon_url = link['href']
                favicon_domain = f"{extract(favicon_url).domain}.{extract(favicon_url).suffix}"

                if favicon_domain == base_domain or not favicon_domain:
                    return 1
        return -1

    except:
        return -1


def port(url):
    # -1 -> Si hay puerto explicito en URL
    #  1 -> Si no hay puerto explicito en URL
    try:
        if ":" in url:
            after_colon = url.split(":")[-1]
            port = after_colon.split("/")[0]
            if port.isdigit():
                port = int(port)
                if (url.startswith("http://") and port != 80) or (url.startswith("https://") and port != 443):
                    return -1
        return 1

    except:
        return -1


def https_token(url):
    # -1 -> Si el dominio contiene token https
    #  1 -> Si el dominio no contiene token https
    try:
        domain = f"{extract(url).domain}.{extract(url).suffix}"

        if 'https' in domain:
            return -1
        return 1

    except:
        return -1


def request_url(url):
    # -1 -> Si más del 61 % de imagenes se añaden de dominios externos
    #  0 -> Si entre el 22% y el 61% de imagenes se añaden de dominios externos
    #  1 -> Otro caso
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        domain = f"{extract(url).domain}.{extract(url).suffix}"
        total_success = 0
        total_count = 0

        for tag, tag_name in zip([soup, soup, soup], ['img', 'audio', 'embed']):
            for element in tag.find_all(tag_name, src=True):
                src_url = element['src']
                src_domain = f"{extract(src_url).domain}.{extract(src_url).suffix}"
                if domain in src_domain or url in src_url:
                    total_success += 1
                total_count += 1

        if total_count == 0:
            return 1

        percent = total_success / total_count
        if percent < 22:
            return 1
        elif 22 <= percent < 61:
            return 0
        else:
            return -1

    except:
        return -1


def url_of_anchor(url):
    # -1 -> Si más del 67 % de tags <a> se añaden de dominios externos
    #  0 -> Si entre el 31% y el 67% de tags <a> se añaden de dominios externos
    #  1 -> Otro caso
    try:
        base_domain = f"{extract(url).domain}.{extract(url).suffix}"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        total_success = 0
        total_count = 0

        for a_tag in soup.find_all('a', href=True):
            href_url = a_tag['href']
            extracted_domain = f"{extract(href_url).domain}.{extract(href_url).suffix}"
            if extracted_domain != base_domain:
                total_success += 1
            total_count += 1

        if total_count == 0:
            return -1

        percentage = (total_success / float(total_count)) * 100
        if percentage < 31.0:
            return 1
        elif 31.0 <= percentage <= 67.0:
            return 0
        else:
            return -1

    except:
        return -1


def links_in_tags(url):
    # -1 -> Si más del 81 % de los links "<Meta>","<Script>" and "<"Link>\" son de distinto dominio
    #  0 -> Si entre el 17% y el 81% de los links "<Meta>","<Script>" and "<"Link>\" son de distinto dominio
    #  1 -> Otro caso
    try:
        base_domain = f"{extract(url).domain}.{extract(url).suffix}"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        total_links = 0
        external_links = 0
        tags_to_check = ['meta', 'script', 'link']

        for tag in tags_to_check:
            for element in soup.find_all(tag):
                if tag == 'meta' and element.get('content'):
                    link = element['content']
                elif tag == 'script' and element.get('src'):
                    link = element['src']
                elif tag == 'link' and element.get('href'):
                    link = element['href']
                else:
                    continue

                if link.startswith(('http://', 'https://')):
                    extracted_domain = f"{extract(link).domain}.{extract(link).suffix}"
                    if extracted_domain.lower() != base_domain.lower():
                        external_links += 1
                    total_links += 1

        if total_links == 0:
            return -1

        external_percentage = (external_links / total_links) * 100
        if external_percentage < 17.0:
            return 1
        elif 17.0 <= external_percentage <= 81.0:
            return 0
        else:
            return -1

    except:
        return -1


def sfh(url):
    # -1 -> SFH contiene un string vacio o “about:blank”
    #  0 -> SFH contiene dominio diferente al de la URL
    #  1 -> Otro caso
    try:

        domain = f"{extract(url).domain}.{extract(url).suffix}"
        response = requests.get(url)
        forms = BeautifulSoup(response.text, 'html.parser').find_all('form', action=True)

        if not forms:
            return 1

        for form in forms:
            action = form['action'].strip()
            if not action or action.lower() == "about:blank":
                return -1
            if domain not in action:
                return 0
        return 1

    except:
        return -1


def submitting_to_email(url):
    # -1 -> Si el código fuente usa mail o mailto
    #  1 -> Si el código fuente no usa mail o mailto
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        for link in soup.find_all('a', href=True):
            if 'mailto:' in link['href']:
                return -1

        if re.search(r"(mail\(\)|mailto:)", response.text):
            return -1
        return 1

    except:
        return -1  # Retorna 0 en caso de error


def abnormal_url(url):
    # -1 -> Si el nombre principal del sitio web no está presente en la URL.
    #  1 -> Si el nombre principal del sitio web está presente en la URL.
    try:
        domain = f"{extract(url).domain}.{extract(url).suffix}"
        whois_domain = whois.whois(domain).domain_name
        if domain.lower() == whois_domain.lower():
            return 1
        else:
            return -1

    except:
        return -1


def redirect(url):
    #  1 -> Si el numero de redirecciones es menor o igual a 1
    #  0 -> Si el numero de redirecciones se encuentra entre 2 y 4
    # -1 -> Otro caso
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        num_redirects = len(response.history)

        if num_redirects <= 1:
            return 1
        elif 2 <= num_redirects < 4:
            return 0
        else:
            return -1

    except:
        return -1


def on_mouseover(url):
    # -1 -> Si el código fuente contiene manipulaciones de la barra de estado mediante 'onmouseover'
    #  1 -> si el código fuente no contiene manipulaciones de la barra de estado mediante 'onmouseover'
    try:
        response_text = requests.get(url).text  # Realiza una solicitud HTTP GET

        if re.search(r"onmouseover.*window\.status", response_text, re.IGNORECASE):
            return -1
        else:
            return 1

    except:
        return -1


def rightclick(url):
    # -1 -> Si el boton derecho está deshabilitado
    #  1 -> Si el boton derecho está habilitado
    try:
        response_text = requests.get(url).text
        if re.findall(r"event\.button\s*==\s*2", response_text):
            return 1
        else:
            return -1

    except:
          return -1


def popupwindow(url):
    # -1 -> Si el popup contiene ventanas de texto, se califica como malicioso
    #  1 -> Si el popup no contiene ventanas de texto, se califica como legítimo
    try:
        response = requests.get(url)

        if re.search(r"alert\(", response.text):
            if re.search(r"<input.*type=['\"]text['\"]", response.text):
                return -1
        return 1

    except:
        return -1


def iframe(url):
    # -1 -> Si el código fuente contiene etiquetas <iframe>
    #  1 -> Si el código fuente no contiene etiquetas <iframe>
    try:
        response_text = requests.get(url).text
        if re.findall(r"<iframe>", response_text):
            return 1
        else:
            return -1

    except:
          return -1


def age_of_domain(url):
    # -1 -> Si la edad del dominio es menor a 6 meses
    #  1 -> Si la edad del dominio es mayor a 6 meses
    try:
        w = whois.whois(url)
        start_date = w.creation_date

        if isinstance(start_date, list):
          start_date = start_date[0]

        start_date = datetime.strptime(str(start_date), "%Y-%m-%d %H:%M:%S")
        current_date = datetime.now()
        age = (current_date - start_date).days

        if age >= 180:
          return 1
        else:
          return -1

    except:
        return -1


def dnsrecord(url):
    # -1 -> No existen registros DNS en la base de datos WHOIS
    #  1 -> Existen registros DNS en la base de datos WHOIS
    try:
        domain_info = whois.whois(url)

        if domain_info.creation_date:
            return 1
        else:
            return -1

    except:
        return -1


def web_traffic(url):
    # -1 -> Si el ranking de VirusTotal califica como malicioso
    #  0 -> Si el ranking de VirusTotal califica como sospechoso
    #  1 -> Si el ranking de VirusTotal califica como legitimo
    try:
        domain = f"{extract(url).domain}.{extract(url).suffix}"
        url_api = f'https://www.virustotal.com/api/v3/urls/{base64.urlsafe_b64encode(domain.encode("utf-8")).decode("utf-8").strip("=")}'
        headers = {'x-apikey': "63179cfe12ffa5c83a90e7f149b1dd55cee7523905ae9335aea7d595b3821e06"}
        response = requests.get(url_api, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'attributes' in data['data'] and 'last_analysis_stats' in data['data'][
                'attributes']:
                malicious = data['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                suspicious = data['data']['attributes']['last_analysis_stats'].get('suspicious', 0)
                if malicious > 0:
                    return -1
                elif suspicious > 0:
                    return 0
                return 1
            else:
                return -1
        else:
            return -1

    except Exception as e:
        return -1


def page_rank(url):
    # -1 -> Si el ranking malicioso de VirusTotal califica mayor a 0.2
    #  1 -> Si el ranking malicioso de VirusTotal califica menor a 0.2
    try:
        domain = f"{extract(url).domain}.{extract(url).suffix}"
        url_api = f'https://www.virustotal.com/api/v3/urls/{base64.urlsafe_b64encode(domain.encode("utf-8")).decode("utf-8").strip("=")}'
        headers = {'x-apikey': "63179cfe12ffa5c83a90e7f149b1dd55cee7523905ae9335aea7d595b3821e06"}
        response = requests.get(url_api, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'attributes' in data['data'] and 'last_analysis_stats' in data['data'][
                'attributes']:
                malicious = data['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                if malicious is not None:
                    pageRank = malicious / 100
                    if pageRank > 0.2:
                        return -1
                    return 1
                else:
                    return -1
            else:
                return -1
        else:
            return -1

    except Exception as e:
        return -1


def google_index(url):
    # -1 -> Si el dominio no se encuentra indexado en google
    #  1 -> Si el dominio se encuentra indexado en google
    try:
        domain = f"{extract(url).domain}.{extract(url).suffix}"
        results = search(domain)

        for _ in results:
            return 1
        return -1

    except:
        return -1


def links_pointing_to_page(url):
    # -1 -> Si el código fuente no posee enlaces apuntandose a sí misma
    #  0 -> Si el código fuente posee 1 o 2 enlaces apuntandose a sí misma
    #  1 -> Otro caso
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        internals_links = [link['href'] for link in links if not link['href'].startswith(('http://', 'https://'))]

        if len(internals_links) == 0:
            return -1
        elif 0 < internals_links <= 2:
            return 0
        else:
            return 1

    except:
        return -1


def statistical_report(url):
    # -1 -> El dominio de la URL coincide con algun top phising domains.
    #  1 -> El dominio de la URL no coincide con algun top phising domains.
    try:
        url_match = re.search(
    'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        if url_match:
            return -1
        return 1

    except:
        return 1


####################
# Aplicacion Flask #
####################
app = Flask(__name__)

algorithm = None
pca = None
scaler = None

@app.route('/url', methods=['POST'])
def process_string_route():
    try:
        data = request.get_json()

        if 'url' not in data:
            return jsonify({"error": "El campo 'url' es requerido"}), 400

        user_url = data['url']
        features = {
            "having_ip_address": having_ip_address(user_url),
            "url_length": url_length(user_url),
            "shortining_service": shortining_service(user_url),
            "having_at_symbol": having_at_symbol(user_url),
            "double_slash_redirecting" : double_slash_redirecting(user_url),
            "prefix_suffix": prefix_suffix(user_url),
            "having_sub_domain": having_sub_domain(user_url),
            "sslfinal_state": sslfinal_state(user_url),
            "domain_registration_length": domain_registration_length(user_url),
            "favicon": favicon(user_url),
            "port": port(user_url),
            "https_token": https_token(user_url),
            "request_url": request_url(user_url),
            "url_of_anchor": url_of_anchor(user_url),
            "links_in_tags": links_in_tags(user_url),
            "sfh": sfh(user_url),
            "abnormal_url": abnormal_url(user_url),
            "submitting_to_email": submitting_to_email(user_url),
            "redirect": redirect(user_url),
            "on_mouseover": on_mouseover(user_url),
            "rightclick": rightclick(user_url),
            "popupwindow": popupwindow(user_url),
            "iframe": iframe(user_url),
            "age_of_domain": age_of_domain(user_url),
            "dnsrecord": dnsrecord(user_url),
            "web_traffic": web_traffic(user_url),
            "page_rank": page_rank(user_url),
            "google_index": google_index(user_url),
            "links_pointing_to_page": links_pointing_to_page(user_url),
            "statistical_report": statistical_report(user_url)
        }

        list_features = list(features.values())
        list_features = np.array(list_features).reshape(1, -1)
        url_api_df = pd.DataFrame(list_features)
        url_api_scaled = scaler.transform(url_api_df)
        url_api_pca = pca.transform(url_api_scaled)
        api_pred_prob = algorithm.predict_proba(url_api_pca)
        api_pred = algorithm.predict(url_api_pca)
        api_pred_prob_list = api_pred_prob.tolist()
        print("Características URL -> " + str(list_features))

        return jsonify({
            "input": user_url,
            "prediction_boolean": int(api_pred[0]),
            "prediction": api_pred_prob_list[0][1]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':

    algorithm, pca, scaler = principal_program()
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
