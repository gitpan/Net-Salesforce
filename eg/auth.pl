#!/usr/bin/env perl
#
# Make sure IO::Socket::SSL is installed and start with
#
# ./eg/auth.pl daemon -l https://*:8081

use FindBin;
BEGIN { unshift @INC, "$FindBin::Bin/../lib" }

use Mojolicious::Lite;
use Net::Salesforce;
use DDP;

get '/' => sub {
  my ($c) = @_;
} => 'index';

post '/auth' => sub {
    my ($c) = @_;
    my $sf = Net::Salesforce->new(
        'key'          => $ENV{SFKEY},
        'secret'       => $ENV{SFSECRET},
        'redirect_uri' => 'https://localhost:8081/callback'
    );
    return $c->redirect_to($sf->authorize_url);
};

get '/callback' => sub {
  my ($c) = @_;
  p $c;
} => 'authenticated';

app->start;

__DATA__

@@ index.html.ep
<html><head><title>index</title></head>
<body>
<form method="post" action="/auth">
<button type="submit">Auth</button>
</form>
</body>
</html>

@@ authenticated.html.ep
<html><head><title>Callback</title></head>
<body>
<h1>Authenticated</h1>
</body>
</html>
