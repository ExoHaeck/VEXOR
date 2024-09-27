import requests
import urllib.parse
import os
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init

init(autoreset=True)

# Cargar User Agents opcionalmente
USER_AGENTS = ["Mozilla/5.0", "Chrome/91.0", "Safari/537.36"]  # Puedes añadir más

def get_random_user_agent():
    """Devuelve un User Agent aleatorio."""
    return random.choice(USER_AGENTS)

def is_valid_utf8(payload):
    """Verifica si el payload es válido en UTF-8."""
    try:
        payload.encode('utf-8').decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def test_open_redirect(url, payloads, max_threads=5):
    """
    Prueba una URL con una lista de payloads para detectar Open Redirects.
    """
    def check_payload(payload):
        # Reemplaza FUZZ por el payload en la URL
        if not is_valid_utf8(payload.strip()):
            print(Fore.RED + f"[!] Payload no válido (UTF-8): {payload.strip()} - Omitiendo...")
            return "", False  # No se considera vulnerable, así que retornamos vacío

        encoded_payload = urllib.parse.quote(payload.strip())
        target_url = f"{url}{encoded_payload}"

        try:
            response = requests.get(target_url, allow_redirects=False, headers={"User-Agent": get_random_user_agent()})
            if 300 <= response.status_code < 400:
                location = response.headers.get("Location", "")
                
                # Manejar problemas de codificación
                try:
                    # Intentar decodificar correctamente
                    location = location.encode('latin1').decode('utf-8')
                except (UnicodeDecodeError, AttributeError):
                    # Si falla la decodificación, mantener la codificación original
                    location = location.encode('latin1').decode('latin1', errors='ignore')

                # Verifica si el redireccionamiento es hacia un dominio externo como Google
                if "google.com" in location:
                    return Fore.GREEN + f"[+] Vulnerable: {Fore.WHITE}{target_url} -> {location}", True
            return Fore.RED + f"[-] No vulnerable: {Fore.WHITE}{target_url}", False
        except requests.RequestException as e:
            print(Fore.RED + f"[!] Error al intentar acceder a {target_url}: {e} - Omitiendo...")
            return "", False

    found_vulnerabilities = 0
    vulnerable_urls = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_payload, payload): payload for payload in payloads}

        for future in as_completed(futures):
            try:
                result, is_vulnerable = future.result()
                print(result)
                if is_vulnerable:
                    found_vulnerabilities += 1
                    vulnerable_urls.append(futures[future])
            except Exception as exc:
                print(Fore.RED + f"[!] Error procesando el payload {futures[future]}: {exc}")

    return found_vulnerabilities, vulnerable_urls

def prompt_for_urls():
    """Pide al usuario ingresar una lista de URLs o un archivo."""
    url_input = input(Fore.LIGHTGREEN_EX + "[+] Ingresa la ruta del archivo con URLs o una sola URL: ").strip()
    if os.path.isfile(url_input):
        with open(url_input) as file:
            urls = [line.strip() for line in file if line.strip()]
    else:
        urls = [url_input]
    return urls

def prompt_for_payloads():
    """Pide al usuario ingresar una lista de payloads o un archivo."""
    payload_input = input(Fore.LIGHTGREEN_EX + "[+] Ingresa la ruta del archivo con los payloads: ").strip()
    if os.path.isfile(payload_input):
        with open(payload_input) as file:
            payloads = [line.strip() for line in file if line.strip()]
    else:
        payloads = [payload_input]  # Permite ingresar un solo payload
    return payloads

def save_results(vulnerable_urls):
    """Guarda las URLs vulnerables en un archivo."""
    save_choice = input(Fore.LIGHTGREEN_EX + "\n[+] ¿Deseas guardar las URLs vulnerables en un archivo? (y/n): ").strip().lower()
    if save_choice == 'y':
        output_file = input(Fore.LIGHTGREEN_EX + "Ingresa el nombre del archivo de salida (por defecto 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
        with open(output_file, 'w') as f:
            for url in vulnerable_urls:
                f.write(url + '\n')
        print(Fore.GREEN + f"URLs vulnerables guardadas en {output_file}")
    else:
        print(Fore.YELLOW + "Resultados no guardados.")

def run_open_redirect_scanner():
    """Ejecuta el escáner de Open Redirect.""" 
    urls = prompt_for_urls()
    payloads = prompt_for_payloads()

    max_threads = input(Fore.LIGHTGREEN_EX + "[+] Ingresa el número de hilos (por defecto 5): ").strip()
    max_threads = int(max_threads) if max_threads.isdigit() else 5

    total_found = 0
    total_scanned = 0
    vulnerable_urls = []

    start_time = time.time()
    for url in urls:
        print(Fore.LIGHTYELLOW_EX + f"\n[!] Escaneando URL: {url}")
        found, urls_with_payloads = test_open_redirect(url, payloads, max_threads)
        total_found += found
        total_scanned += len(payloads)
        vulnerable_urls.extend(urls_with_payloads)

    # Imprimir resumen
    print(Fore.GREEN + f"\n[i] Escaneo completado. Total de vulnerabilidades encontradas: {total_found}")
    print(Fore.CYAN + f"Total de URLs escaneadas: {len(urls)} con {total_scanned} payloads.")
    print(Fore.YELLOW + f"Tiempo tomado: {int(time.time() - start_time)} segundos")

    # Guardar resultados si es necesario
    save_results(vulnerable_urls)

if __name__ == "__main__":
    print("""\033[38;5;129m
 ___      ___ _______      ___    ___ ________  ________     
|\  \    /  /|\  ___ \    |\  \  /  /|\   __  \|\   __  \    
\ \  \  /  / | \   __/|   \ \  \/  / | \  \|\  \ \  \|\  \   
 \ \  \/  / / \ \  \_|/__  \ \    / / \ \  \\\  \ \   _  _\  
  \ \    / /   \ \  \_|\ \  /     \/   \ \  \\\  \ \  \\  \| 
   \ \__/ /     \ \_______\/  /\   \    \ \_______\ \__\\ _\ 
    \|__|/       \|_______/__/ /\ __\    \|_______|\|__|\|__|  
                          |__|/ \|__|                        
\033[0m""")

    description = f"""
{Fore.GREEN}Esta herramienta está diseñada para
===================================

> Buscar OR (Open Redirects) en un listado de URL o por URL única{Fore.RESET}
"""

    rights_and_blog = f"""
{Fore.LIGHTMAGENTA_EX}Realizado por Mauro Flair Aka. Agrawain.{Fore.RESET}
{Fore.LIGHTMAGENTA_EX}Web: https://www.hacksyndicate.tech/{Fore.RESET}
"""

    print(description)
    print(rights_and_blog)

    try:
        run_open_redirect_scanner()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Escaneo abortado por el usuario.")
