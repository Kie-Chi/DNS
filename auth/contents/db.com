$TTL    1
@       IN      SOA     ns-auth.example.com. admin.example.com. (
                              2024080201 ; Serial
                              3600       ; Refresh
                              1800       ; Retry
                              604800     ; Expire
                              1 )    ; Negative Cache TTL

@       IN      NS      ns-auth.example.com.
ns-auth.example.com.  IN      A       10.3.0.3

a.com.  IN  NS  ns-auth.a.com.
ns-auth.a.com.  IN  A  10.3.0.4

b.com.  IN  NS  ns-auth.b.com.
ns-auth.b.com.  IN  A   10.3.0.5

c.com.  IN  NS  ns-auth.c.com.
ns-auth.c.com.  IN  A   10.3.0.6

