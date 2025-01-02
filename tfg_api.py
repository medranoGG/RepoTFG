import base64
import numpy as np
import pandas as pd
from googlesearch import search
from tldextract import extract
from bs4 import BeautifulSoup
from datetime import datetime
from flask import Flask, request, jsonify
import requests
import whois
import time
import re
########################
from tfg_code import principal_program


def having_ip_address(url): # ✅✅✅
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


def url_length(url):# ✅✅✅
    #  1 -> Si la longitud es menor que X
    #  0 -> Si la longitu está entre 54 y 75
    # -1 -> Si la longitud es mayor que X

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


def shortining_service(url):# ✅✅✅
    # -1 -> Si la URL usa servicios
    #  1 -> Si la longitud es menor que X

    try:
        shortening_services = [
            "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd",
            "buff.ly", "adf.ly", "bit.do", "shorte.st", "mcaf.ee",
            "soo.gd", "yourls.org", "rebrandly.com", "clickmeter.com",
            "tiny.cc", "cutt.ly", "v.gd", "qr.ae", "bl.ink", "short.io"
        ]

        # Extraer dominio y TLD
        domain = f"{extract(url).domain}.{extract(url).suffix}"

        # Verificar si el dominio está en la lista de acortadores
        if domain in shortening_services:
            return -1  # Sospechoso (acortador)
        else:
            return 1  # Legítimo (no acortador)
    except:
        return -1


def having_at_symbol(url):# ✅✅✅
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
    try:
        if url.rfind('//') >= 7:
            return -1
        else:
            return 1

    except:
        return -1


def prefix_suffix(url):# ✅✅✅
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


def having_sub_domain(url):# ✅✅✅
    # -1 -> Tiene más de un subdominio
    #  0 -> Tiene un subdominio
    #  1 -> No tiene subdominio

    try:
        subdomain = extract(url).subdomain
        #print(subdomain)
        #print(subdomain.count('.'))

        if subdomain.count('.') > 0:
            return -1
        elif subdomain:
            return 0
        else:
            return 1
    except:
        return -1


def sslfinal_state(url):# ✅✅✅
    #  1 -> El sitio usa HTTPS
    # -1 -> El sitio no usa HTTPS

    try:
        pattern = r'^https://'

        # Verificar si el URL empieza con 'https://'
        if re.match(pattern, url):
            return 1  # HTTPS está presente
        else:
            return -1  # No usa HTTPS
    except:
        return -1


def domain_registration_length(url):# ✅✅✅
    # -1 -> Si el dominio expira en menos de un año
    #  1 -> Si el dominio expira en más de un año

    try:
        w = whois.whois(url)
        # Asegurarse de que la fecha de expiración está disponible
        expiration_date = w.expiration_date
        # Si hay varias fechas de expiración, tomamos la primera
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        # Convertimos la fecha de expiración a un objeto datetime
        expiration_date = datetime.strptime(str(expiration_date), "%Y-%m-%d %H:%M:%S")
        # Obtenemos la fecha actual
        current_date = datetime.now()

        # Calculamos la diferencia en días entre la fecha de expiración y la fecha actual
        delta = (expiration_date - current_date).days
        #print(delta)

        # Clasificamos el dominio basado en la duración
        if delta <= 365:
            return -1
        else:
            return 1
    except:
        return -1


def favicon(url):# ✅✅✅
    '''
    Si el favicon se carga desde un dominio distinto al que se muestra en la barra de direcciones, es probable que la página web se considere un intento de phishing.
    '''

    try:
        # Usamos urlparse para obtener el dominio de la URL.
        base_domain = f"{extract(url).domain}.{extract(url).suffix}"

        # Realizamos la solicitud HTTP para obtener el contenido HTML.
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Buscamos todas las etiquetas <link> en el <head> de la página.
        for head in soup.find_all('head'):
            for link in head.find_all('link', href=True):
                favicon_url = link['href']

                # Usamos urlparse para analizar la URL del favicon.
                favicon_domain = f"{extract(favicon_url).domain}.{extract(favicon_url).suffix}"

                # Comprobamos si el favicon está en el mismo dominio o en un dominio diferente.
                if favicon_domain == base_domain or not favicon_domain:
                    #print(favicon_domain)
                    #print(base_domain)
                    return 1  # Favicon legítimo (mismo dominio o URL relativa).

        return -1  # Favicon de dominio externo (posible phishing).

    except:
        return -1


def port(url):
    # -1 -> Si hay puerto explicito en URL, marcamos como phishing
    #  1 -> Si no hay puerto explicito en URL, marcamos como legitimo
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
    try:
        # Extraer los componentes del dominio usando tldextract
        domain = f"{extract(url).domain}.{extract(url).suffix}"

        if 'https' in domain:
            return -1  # Indica posible phishing
        return 1  # URL legítima

    except Exception as e:
        return -1


def request_url(url):# ✅✅✅
    try:
        # Obtener la respuesta y parsear el HTML
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extraer el dominio de la URL
        domain = f"{extract(url).domain}.{extract(url).suffix}"

        total_success = 0
        total_count = 0

        # Evaluar imágenes, audios y elementos embed
        for tag, tag_name in zip([soup, soup, soup], ['img', 'audio', 'embed']): # Sacamos imagen audio y embebed
            for element in tag.find_all(tag_name, src=True):
                #print(element)
                src_url = element['src'] # origen de el elemento
                src_domain = f"{extract(src_url).domain}.{extract(src_url).suffix}"
                #print(src_url)
                if domain in src_domain or url in src_url: # comprobamos si el origen y la url tieien el mismo dominio
                    total_success += 1
                total_count += 1

        #print(total_success)
        #print(total_count)

        if total_count == 0:
            return 1

        # Calcular el porcentaje de recursos externos
        percent = total_success / total_count
        #print(percent)

        # Clasificación según el porcentaje
        if percent < 22:
            return 1  # Legítimo
        elif 22 <= percent < 61:
            return 0  # Sospechoso
        else:
            return -1  # Phishing

    except:
        return -1

def url_of_anchor(url):# ✅✅✅
    # 1: Contiene elementos definidos por una etiqueta <a>
    # 2: Si el ancla no enlaza con ninguna página web.

    try:
        # Extraemos el dominio base de la URL
        base_domain = f"{extract(url).domain}.{extract(url).suffix}"

        # Realizamos la solicitud HTTP para obtener el contenido HTML
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        total_success = 0
        total_count = 0

        # Buscamos todas las etiquetas <a> en el HTML
        for a_tag in soup.find_all('a', href=True):
            href_url = a_tag['href']

            extracted_domain = f"{extract(href_url).domain}.{extract(href_url).suffix}"
            #print(extracted_domain)
            if extracted_domain != base_domain:
                total_success += 1  # Enlace a dominio externo

            total_count += 1

        if total_count == 0:
            return -1

        # Calcular el porcentaje de enlaces externos
        percentage = (total_success / float(total_count)) * 100

        # Clasificación según el porcentaje
        if percentage < 31.0:
            return 1  # Legítimo
        elif 31.0 <= percentage <= 67.0:
            return 0  # Sospechoso
        else:
            return -1  # Phishing

    except:
        return -1

def links_in_tags(url):# ✅✅✅
    """
    Analiza los enlaces en etiquetas <meta>, <script> y <link> en una página web,
    clasificando el sitio como Legítimo, Sospechoso o Phishing basado en el porcentaje
    de enlaces que apuntan a dominios externos.

    :param url: URL del sitio a analizar
    :return: 1 para Legítimo, 0 para Sospechoso, -1 para Phishing
    """
    try:
        # Extraer el dominio base de la URL principal
        base_domain = f"{extract(url).domain}.{extract(url).suffix}"

        # Realizar la solicitud HTTP para obtener el contenido HTML
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        total_links = 0
        external_links = 0

        # Analizar etiquetas <meta>, <script> y <link>
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

                # Validar si el enlace tiene un dominio diferente
                if link.startswith(('http://', 'https://')):
                    extracted_domain = f"{extract(link).domain}.{extract(link).suffix}"
                    #print(str(extracted_domain) + "==" + str(base_domain))
                    if extracted_domain.lower() != base_domain.lower():
                        external_links += 1
                    total_links += 1

        if total_links == 0:
            return -1  # No hay enlaces evaluables

        # Calcular el porcentaje de enlaces externos
        external_percentage = (external_links / total_links) * 100
        #print(external_percentage)

        # Clasificar según el porcentaje
        if external_percentage < 17.0:
            return 1  # Legítimo
        elif 17.0 <= external_percentage <= 81.0:
            return 0  # Sospechoso
        else:
            return -1  # Phishing

    except:
        return -1


def sfh(url):# ✅✅✅
    """
    Evalúa los formularios en la página analizando el atributo 'action'
    para clasificar la página como legítima, sospechosa o phishing:

    - Si no hay formularios, clasifica como legítima (1).
    - Si algún formulario tiene un 'action' vacío o "about:blank", clasifica como phishing (-1).
    - Si algún formulario tiene un 'action' que apunta a un dominio externo, clasifica como sospechosa (0).
    - Si todos los formularios son válidos y tienen un 'action' del mismo dominio, clasifica como legítima (1).

    :return: 1 para legítimo, 0 para sospechoso, -1 para phishing.
    """
    try:

        domain = f"{extract(url).domain}.{extract(url).suffix}"
        response = requests.get(url)
        forms = BeautifulSoup(response.text, 'html.parser').find_all('form', action=True)

        if not forms:  # Si no hay formularios, clasificar como legítimo
            return 1

        for form in forms:
            action = form['action'].strip()  # Limpiar espacios innecesarios del atributo 'action'

            # Regla 1: Si 'action' está vacío o es "about:blank"
            if not action or action.lower() == "about:blank":
                return -1

            # Regla 2: Si 'action' apunta a un dominio externo
            if domain not in action:
                return 0

        # Regla 3: Si todos los formularios tienen un 'action' válido y del mismo dominio
        return 1

    except:
        return -1


def submitting_to_email(url):
    # -1 -> Si el código fuente usa mail o mailto, categorizamos como phishing
    #  1 -> Si el código fuente no usa mail o mailto, categorizamos como legítimo

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Buscamos enlaces mailto: en el HTML
        for link in soup.find_all('a', href=True):
            if 'mailto:' in link['href']:
                return -1  # Indica posible phishing

        # Verificamos si hay alguna función mail() o mailto: en el código fuente
        if re.search(r"(mail\(\)|mailto:)", response.text):
            return -1  # Indica posible phishing

        return 1  # Si no se detecta nada sospechoso

    except:
        return -1  # Retorna 0 en caso de error


def abnormal_url(url):# ✅✅✅
    '''
    La función detecta si el nombre del host (es decir, el nombre principal del sitio web, como example.com) está presente en la URL.
    '''
    try:
        # Parsear la URL para extraer el dominio
        domain = f"{extract(url).domain}.{extract(url).suffix}"
        #print(domain)

        # Obtener el registro WHOIS
        whois_domain = whois.whois(domain).domain_name
        #print(whois_domain)

        # Comparar el contenido de la página con los datos de WHOIS
        if domain.lower() == whois_domain.lower():
            return 1  # Host coincide, es legítimo
        else:
            return -1  # Host no coincide, posible phishing
    except:
        return -1


def redirect(url):# ✅✅✅
    """
    Analiza la cantidad de redirecciones que tiene una URL y clasifica el sitio web como:
    - Legítimo (1): Si el número de redirecciones es 1 o menos.
    - Sospechoso (0): Si el número de redirecciones está entre 2 y 3.
    - Phishing (-1): Si el número de redirecciones es 4 o más.

    :param url: URL del sitio a analizar.
    :return: 1 para legítimo, 0 para sospechoso, -1 para phishing.
    """

    try:
        # Realiza la solicitud y sigue redirecciones automáticamente
        response = requests.get(url, allow_redirects=True, timeout=10)

        # Contar el número de redirecciones
        num_redirects = len(response.history)
        #
        #print(num_redirects)

        # Clasificación según el número de redirecciones
        if num_redirects <= 1:
            return 1  # Legítimo
        elif 2 <= num_redirects < 4:
            return 0  # Sospechoso
        else:
            return -1  # Phishing

    except:
        return -1


def on_mouseover(url):# ✅✅✅
    """
    Verifica si el código fuente contiene manipulaciones de la barra de estado mediante 'onmouseover'.

    :param response_text: Contenido HTML de la página web como texto
    :return: 1 si se detecta manipulación de la barra de estado (Phishing), -1 en caso contrario (Legítimo)
    """
    try:

        response_text = requests.get(url).text  # Realiza una solicitud HTTP GET
        # Buscar 'onmouseover' combinado con manipulaciones de 'window.status'
        if re.search(r"onmouseover.*window\.status", response_text, re.IGNORECASE):
            return -1  # Phishing detectado
        else:
            return 1  # Legítimo
    except:
        return -1


def rightclick(url):# ✅✅✅
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
        # Buscar 'alert(' para detectar ventanas emergentes
        response = requests.get(url)

        if re.search(r"alert\(", response.text):
            # Buscar campos de texto para identificar posibles intentos de phishing
            if re.search(r"<input.*type=['\"]text['\"]", response.text):
                return -1  # Se encontró un formulario de entrada de texto

        return 1

    except:
        return -1


def iframe(url):# ✅✅✅
    try:
        response_text = requests.get(url).text
        if re.findall(r"<iframe>", response_text):
            return 1
        else:
            return -1
    except:
          return -1


def age_of_domain(url):# ✅✅✅
    #  1 -> Si la "edad" del dominio es mayor a 6 meses
    # -1 -> Si la "edad" del dominio es menor a 6 meses

    try:
        w = whois.whois(url)

        # Asegurarse de que la fecha de creación está disponible
        start_date = w.creation_date

        # Si hay varias fechas de creación, tomamos la primera
        if isinstance(start_date, list):
          start_date = start_date[0]

        # Convertimos la fecha de creación a un objeto datetime
        start_date = datetime.strptime(str(start_date), "%Y-%m-%d %H:%M:%S")

        # Obtenemos la fecha actual
        current_date = datetime.now()

        # Calculamos la diferencia en días entre la fecha de creación y la fecha actual
        age = (current_date - start_date).days

        # Clasificamos el dominio basado en la edad
        if age >= 180:  # Si la edad del dominio es mayor o igual a 6 meses
          return 1  # Legítimo
        else:
          return -1  # Phishing
    except:
        return -1


def dnsrecord(url):# ✅✅✅
    """
    Verifica la existencia de registros DNS para el dominio usando la base de datos WHOIS.

    :param url: URL del dominio a analizar
    :return: -1 si no hay registros DNS (Phishing), 1 si hay registros DNS (Legítimo)
    """
    try:
        # Intentar obtener la información WHOIS del dominio
        domain_info = whois.whois(url)

        # Verificar si existe una fecha de creación
        if domain_info.creation_date:
            return 1  # Legítimo
        else:
            return -1  # Phishing (no hay registro)

    except:
        return -1



def web_traffic(url):# ✅✅✅
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



def page_rank(url):# ✅✅✅
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


def google_index(url):# ✅✅✅
    try:
        site = search("Google")
        #print(site)
        if site:
            return 1
        else:
            return -1
    except:
        return -1


def links_pointing_to_page(url):# ✅✅✅
    """
    Clasifica una página web como Legítima, Sospechosa o Phishing
    basado en el número de enlaces apuntados a la propia pagina. Las phishing no tienen enlaces internos

    :param url: URL del sitio a analizar
    :return: 1 para Legítima, 0 para Sospechosa, -1 para Phishing
    """
    try:
        # Realizar una solicitud HTTP para obtener el contenido HTML
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Buscar todas las etiquetas <a> con enlaces
        links = soup.find_all('a', href=True)
        internals_links = [link['href'] for link in links if not link['href'].startswith(('http://', 'https://'))]
        if len(internals_links) == 0:
            return -1  # Phishing
        elif 0 < internals_links <= 2:
            return 0  # Sospechosa
        else:
            return 1  # Legítima

    except:
        return -1


def statistical_report(url):# 🟨🟨🟨
    try:
        url_match = re.search(
    'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        if url_match:
            return -1
        return 1

    except:
        return 1


"""##**2. Flask**"""
app = Flask(__name__)
algorithm = None
pca = None
scaler = None
# Ruta para procesar el string
@app.route('/url', methods=['POST'])
def process_string_route():
    try:
        # Obtener el JSON enviado por el usuario
        data = request.get_json()

        # Validar que el JSON tenga el campo 'url'
        if 'url' not in data:
            return jsonify({"error": "El campo 'url' es requerido"}), 400

        user_url = data['url']

        # Crear el diccionario con los resultados
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
        print(list_features)

        # Reformar el array a 2D para que sea compatible con el modelo
        list_features = np.array(list_features).reshape(1, -1)

        # Hacer la predicción usando el modelo entrenado
        url_api_df = pd.DataFrame(list_features)
        # Escalar los datos con el scaler entrenado
        url_api_scaled = scaler.transform(url_api_df)
        # Aplicar PCA a los datos escalados
        url_api_pca = pca.transform(url_api_scaled)
        # Hacer la predicción con el modelo entrenado
        api_pred_prob = algorithm.predict_proba(url_api_pca)
        api_pred = algorithm.predict(url_api_pca)
        api_pred_prob_list = api_pred_prob.tolist()

        # Devolver la predicción como JSON
        return jsonify({
            "input": user_url,
            "prediction": api_pred_prob_list[0][1]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Iniciar la aplicación
if __name__ == '__main__':

    algorithm, pca, scaler = principal_program()
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)

