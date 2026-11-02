"""Show that the same TCP details make the same connection ID."""

from sec.conn_id import create_connection_id


first_id = create_connection_id(
    "10.0.1.2", 50122, "10.0.3.2", 9000, 1000, 2000
)
same_id = create_connection_id(
    "10.0.1.2", 50122, "10.0.3.2", 9000, 1000, 2000
)
other_id = create_connection_id(
    "10.0.1.2", 50123, "10.0.3.2", 9000, 3000, 4000
)

print("Same connection gives same ID:", first_id == same_id)
print("Changed connection gives a different ID:", first_id != other_id)
print("ID size in bytes:", len(first_id))
