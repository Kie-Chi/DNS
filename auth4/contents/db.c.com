$TTL 1
@       IN      SOA     ns-auth.c.com. admin.c.com. ( 1 1H 30M 1W 1 )
@       IN      NS      ns-auth.c.com.
ns-auth.c.com.  IN  A   10.3.0.6

sub1.c.com.  IN  NS  sub2.a.com.
sub2.c.com.  IN  NS  sub3.a.com.
sub3.c.com.  IN  NS  sub1.a.com.

www      IN      A       3.3.3.3