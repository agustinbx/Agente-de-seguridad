"""
Script descartable para confirmar que la GEMINI_API_KEY funciona.
Correr: python test_gemini.py
Si todo esta bien, imprime una respuesta corta del modelo.
Una vez confirmado, se puede borrar este archivo.
"""

import os

from dotenv import load_dotenv
from google import genai

load_dotenv()

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

response = client.models.generate_content(
    model="gemini-3.5-flash",
    contents="Respondeme con una sola palabra: funciona.",
)

print(response.text)
