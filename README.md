# VEXOR

![image](https://github.com/user-attachments/assets/6a341460-619b-4936-bd17-5c6a5bde7d80)


# Open Redirect Scanner 

## Descripción

Esta herramienta está diseñada para escanear URLs en busca de vulnerabilidades de Open Redirect. Permite probar una lista de payloads en múltiples URLs y detectar si el redireccionamiento se realiza hacia dominios externos no deseados (como Google) sin autorización adecuada. Está equipada con soporte para múltiples hilos (threads) para realizar el escaneo de forma eficiente.

## Características

- **Soporte para múltiples hilos:** Especifica el número de hilos que quieres usar para escanear varias URLs al mismo tiempo.
- **Uso de User Agents aleatorios:** Evita bloqueos de WAF rotando entre diferentes User Agents para cada solicitud.
- **Identificación de Open Redirects:** Escanea las URLs con payloads para detectar redirecciones no autorizadas hacia dominios externos.
- **Guardado de resultados:** Te permite guardar las URLs vulnerables en un archivo al finalizar el escaneo.

## Requisitos

- Python 3.x
- Módulos necesarios:
  - `requests`
  - `colorama`
  - `concurrent.futures`

Para instalar los módulos necesarios, ejecuta:

```bash
pip install requests colorama


