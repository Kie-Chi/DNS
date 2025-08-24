$TTL 1
@       IN      SOA     ns-auth.a.com. admin.a.com. ( 1 1H 30M 1W 1 )
@       IN      NS      ns-auth.a.com.
ns-auth.a.com.  IN  A   10.3.0.4

sub1.a.com.  IN  NS  sub1.b.com.
sub2.a.com.  IN  NS  sub2.b.com.
sub3.a.com.  IN  NS  sub3.b.com.

www      IN      A       1.1.1.1