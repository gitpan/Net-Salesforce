requires 'Digest::SHA';
requires 'Mojo::Base';
requires 'Mojo::Parameters';
requires 'Mojo::URL';
requires 'Mojo::UserAgent';
requires 'Mojolicious::Lite';

on build => sub {
    requires 'Test::More';
    requires 'Test::Pod';
    requires 'Test::Pod::Coverage';
};

on test => sub {
    requires 'Test::More';
};
