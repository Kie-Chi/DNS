$TTL    86400
@       IN      SOA     ns-auth.example.com. admin.example.com. (
                              2024080201 ; Serial
                              3600       ; Refresh
                              1800       ; Retry
                              604800     ; Expire
                              86400 )    ; Negative Cache TTL

@       IN      NS      ns-auth.example.com.
example.com. IN     NS      ns-auth.example.com.
ns-auth.example.com.  IN      A       10.10.0.7