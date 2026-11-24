"""Test fixture for ja4p-python-incomplete-url-substring-sanitization."""


def bad_startswith(image: str) -> bool:
    # ruleid: ja4p-python-incomplete-url-substring-sanitization
    return image.startswith("gcr.io/")


def bad_contains(url: str) -> bool:
    # ruleid: ja4p-python-incomplete-url-substring-sanitization
    return "docker.io/" in url


def good_partition(image: str) -> bool:
    # ok: ja4p-python-incomplete-url-substring-sanitization
    host, sep, _ = image.partition("/")
    return bool(sep) and host == "gcr.io"
