package Crypt::XXTEA::CImpl;

use 5.008008;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

our @EXPORT_OK = qw(
	xxtea_decrypt
	xxtea_encrypt
	long2str
	str2long
);

our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Crypt::XXTEA::CImpl', $VERSION);


1;
__END__

=head1 NAME

Crypt::XXTEA::CImpl - Perl extension for encryption arithmetic module.

=head1 SYNOPSIS

	use Crypt::XXTEA::CImpl qw(
		xxtea_decrypt
		xxtea_encrypt
	);
	$crypted = xxtea_encrypt($message,$key);
	$message = xxtea_encrypt($crypted,$key);

=head1 DESCRIPTION

XXTEA is a secure and fast encryption algorithm. It's suitable for web development. This module allows you to encrypt or decrypt a string using the algorithm.

=head2 EXPORT

None by default.

=head1 SEE ALSO


=head1 AUTHOR

Ildar Efremov, E<lt>iefremov@2reallife.com<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Ildar Efremov

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut
