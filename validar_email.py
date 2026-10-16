import re

_EMAIL_REGEX = re.compile(
    r"^(?!\.)"                                   # não começa com ponto
    r"[A-Za-z0-9._%+-]{1,64}"                    # parte local
    r"(?<!\.)@"                                  # não termina com ponto antes do @
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"  # subdomínios
    r"[A-Za-z]{2,}$"                             # TLD
)


def validar_email(email: str) -> bool:
    """Retorna True se `email` tiver um formato de e-mail válido."""
    if not isinstance(email, str) or len(email) > 254:
        return False
    if ".." in email:
        return False
    return _EMAIL_REGEX.fullmatch(email) is not None


if __name__ == "__main__":
    testes = [
        "usuario@exemplo.com",
        "nome.sobrenome+tag@sub.dominio.com.br",
        "sem-arroba.com",
        "@dominio.com",
        "usuario@dominio",
        "usuario@.com",
        "usu..ario@dominio.com",
        "usuario@dominio.c",
    ]
    for t in testes:
        print(f"{t!r}: {validar_email(t)}")
