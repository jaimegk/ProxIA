"""Prueba de round-trip: real -> anonimizado (lo que ve la IA) -> des-anonimizado."""
import asyncio
from src.anonymizer import anonymize, deanonymize

SAMPLE = """\
Expediente del paciente Marcos Tovar (DNI 12345678Z), fecha de nacimiento 1985-03-12.
MRN: A1234567. Teléfono de contacto: +34 612 345 678.
Email: marcos.tovar@clinicasanluis.es
Pago de la consulta con tarjeta 4532015112830366 (IBAN ES9121000418450200051332, SWIFT BSCHESMMXXX).
Servidor del historial: hospital-db-01 (192.168.10.5)
Clave del backup: AKIAIOSFODNN7EXAMPLE
"""


async def main():
    print("=" * 70)
    print("1) ORIGINAL (lo que sale de tu herramienta):")
    print("=" * 70)
    print(SAMPLE)

    anon = await anonymize(SAMPLE, is_tool_output=True)
    print("=" * 70)
    print("2) ANONIMIZADO (lo UNICO que viajaria a la IA en la nube):")
    print("=" * 70)
    print(anon)

    back = deanonymize(anon)
    print("=" * 70)
    print("3) DES-ANONIMIZADO (lo que tu terminal recupera):")
    print("=" * 70)
    print(back)

    print("=" * 70)
    print("Round-trip exacto:", "OK ✅" if back == SAMPLE else "DIFERENTE ❌")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
