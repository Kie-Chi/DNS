$TTL 1
@       IN      SOA     ns-auth.b.com. admin.b.com. ( 1 1H 30M 1W 1 )
@       IN      NS      ns-auth.b.com.
ns-auth.b.com.  IN  A   10.3.0.5

sub1.b.com.  IN  NS  sub1.c.com.
sub2.b.com.  IN  NS  sub2.c.com.
sub3.b.com.  IN  NS  sub3.c.com.

www      IN      A       2.2.2.2