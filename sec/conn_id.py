"""Create a stable identifier from the endpoints and TCP opening numbers."""

import hashlib


def create_connection_id(
    client_ip,
    client_port,
    server_ip,
    server_port,
    client_isn,
    server_isn,
):
    parts = (
        client_ip,
        str(client_port),
        server_ip,
        str(server_port),
        str(client_isn),
        str(server_isn),
    )
    connection_text = "|".join(parts)
    return hashlib.sha256(connection_text.encode("utf-8")).digest()
