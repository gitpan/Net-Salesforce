package Net::Salesforce;

use Mojo::Base -base;
use Mojo::UserAgent;
use Mojo::URL;
use Mojo::Parameters;
use Digest::SHA;

our $VERSION = '0.01';

has 'key';
has 'secret';
has 'redirect_uri' => 'https://localhost:8081/callback';
has 'access_token_url' => 'https://na15.salesforce.com/services/oauth2/token';
has 'scope' => 'api';
has 'response_type' => 'code';
has 'params' => sub {
    my $self = shift;
    return {
        client_id     => $self->key,
        client_secret => $self->secret,
        redirect_uri  => $self->redirect_uri,
    };
};

has 'json' => sub {
    my $self = shift;
    my $json = Mojo::JSON->new;
    return $json;
};

has 'ua' => sub {
    my $self = shift;
    my $ua = Mojo::UserAgent->new;
    $ua->transactor->name("Net::Salesforce/$VERSION");
    return $ua;
};

sub verify_signature {
    my ($self, $payload) = @_;
    my $sha = Digest::SHA->new(256);
    $sha->add($self->secret);
    $sha->add($payload->{id});
    $sha->add($payload->{issued_at});
    $sha->b64digest eq $payload->{signature};
}

sub refresh {
    my $self = shift;
    $self->params->{grant_type} = 'refresh_token';
    return $self->oauth2;
}

sub password {
    my $self = shift;
    $self->params->{grant_type} = 'password';
    return $self->oauth2;
}

sub authenticate {
    my $self = shift;
    $self->params->{grant_type} = 'authorization_code';
    return $self->oauth2;
}

sub authorize_url {
    my $self = shift;
    $self->params->{response_type} = 'code';
    my $url =
      Mojo::URL->new('https://na15.salesforce.com/services/oauth2/authorize')
      ->query($self->params);
    return $url->to_string;
}

sub oauth2 {
    my $self = shift;
    my $tx = $self->ua->post($self->access_token_url => form => $self->params);

    die $tx->res->body unless $tx->success;

    my $payload = $self->json->decode($tx->res->body);
    die "Unable to verify signature" unless $self->verify_signature($payload);

    return $payload;
}

1;
__END__

=encoding utf-8

=head1 NAME

Net::Salesforce - Authentication against Salesforce OAuth 2 endpoints.

=head1 SYNOPSIS

  use Net::Salesforce;

=head1 DESCRIPTION

Net::Salesforce is an authentication module for Salesforce OAuth 2.

=head1 ATTRIBUTES

=head2 authorize_url

=head2 key

=head2 params

=head2 password

=head2 redirect_uri

=head2 response_type

=head2 scope

=head2 secret

=head2 ua

A L<Mojo::UserAgent> object.

=head2 json

A L<Mojo::JSON> object.

=head1 METHODS

=head2 verify_signature

=head2 refresh

=head2 oauth2

=head2 access_token_url

=head2 authenticate

=head1 AUTHOR

Adam Stokes E<lt>adamjs@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright 2014- Adam Stokes

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

=cut
