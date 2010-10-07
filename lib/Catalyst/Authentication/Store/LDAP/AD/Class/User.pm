package Catalyst::Authentication::Store::LDAP::AD::Class::User;

use strict;
use warnings;
use base qw/Catalyst::Authentication::User/;
use base qw/Class::Accessor::Fast/;
use Catalyst::Authentication::Store::LDAP::AD::Simple;

BEGIN {
	__PACKAGE__->mk_accessors(qw/config resultset _user _ldap/);
}

sub new {
	my ( $class, $config, $c) = @_;

	if (!defined($config->{'user_model'})) {
		$config->{'user_model'} = $config->{'user_class'};
	}

	my $lds = Catalyst::Authentication::Store::LDAP::AD::Simple->new(
		ldap_domain => $config->{'ldap_domain'},
		global_user => $config->{'ldap_global_user'},
		global_pass => $config->{'ldap_global_pass'},
		ldap_base 	=> $config->{'ldap_base'},
		ldap_filter => $config->{'ldap_filter'},
		timeout     => $config->{'ldap_timeout'},
	);

	my $self = {
		config => $config,
		_user => undef,
		_ldap => $lds
	};

	bless $self, $class;

	return $self;
}

sub load {
	my ($self, $authinfo, $c) = @_;

	# get user authorization flag

#use Data::Dumper;
#warn "=" x 100 . "LOAD:AUTHINFO" . Dumper($authinfo);

	$self->_ldap->setup();

	my $user = $self->_ldap->get_user(
		login 		=> $authinfo->{'login'},
		password 	=> $authinfo->{'password'}
	);

#	warn "=/" x 100 . " USER in load :" . Dumper $user;

	if ($user) {

		use Digest::MD5 qw/md5_hex/;

		$user->replace ( 'objectGUID' => md5_hex $user->get_value('objectGUID') );

		no Digest::MD5;

		$self->_user($user);

#warn("UP" x 100 . "USER.pm" . Dumper($user));

		return $self;

	} else {
			return undef;
	}

}

sub supported_features {
	my $self = shift;
	return {
		session => 1,
		password => { self_check => 1, },
	};
}

sub for_session {
	my $self = shift;

#use Data::Dumper;
#warn "r->" x 1000 . Dumper($self);
	#use Storable qw/freeze/;
	#my $frozenuser = freeze $self->_user;
	#no Storable;

	return $self->_user;
}

sub from_session {
	my ($self, $frozenuser, $c) = @_;

	#use Storable qw/thaw/;
	#$frozenuser = thaw($frozenuser);
	#no Storable;

	$self->_user($frozenuser);

#use Data::Dumper;
#warn "<-m" x 1000 . Dumper($self);

	return $self;
}

sub get {
	my ($self, $field) = @_;

	if ($field) {

#use Data::Dumper;
#warn(Dumper($self->_user->{'asn'}->{'attributes'}));

		# Can't use method "get_value" because of reason below:
		# Cache::FastMmap can't correctly store and retieve Net::LDAP::Entry object
		# or any other BLESSED OBJECT correctly. I suppose that mmap could not correctly
		# bless object hash when user want to retrieve data fom store.
		#$field = $self->_user->get_value($field);

		# get entry attribute
		$field = (grep { $_->{'type'} eq $field; } @{$self->_user->{'asn'}->{'attributes'}})[0]->{'vals'}->[0];

		Encode::_utf8_on($field);

		return $field;

	} else {
		return undef;
	}
}

sub get_object {
	my ($self) = @_;
	return $self->_user;
}

sub check_password {
	my ($self, $password) = @_;

	# get user distinguished name
	my $dn = $self->_user->dn() or Catalyst::Exception->throw("no user found! : $!\n");

	return $self->_ldap->authenticate($dn, $password);
}

1;
__END__

=head1 NAME

Catalyst::Authentication::Store::DBIx::Class::User - The backing user
class for the Catalyst::Authentication::Store::DBIx::Class storage
module.

=head1 VERSION

This documentation refers to version 0.10.

=head1 SYNOPSIS

Internal - not used directly, please see
L<Catalyst::Authentication::Store::DBIx::Class> for details on how to
use this module. If you need more information than is present there, read the
source.



=head1 DESCRIPTION

The Catalyst::Authentication::Store::DBIx::Class::User class implements user storage
connected to an underlying DBIx::Class schema object.

=head1 SUBROUTINES / METHODS

=head2 new

Constructor.

=head2 load ( $authinfo, $c )

Retrieves a user from storage using the information provided in $authinfo.

=head2 supported_features

Indicates the features supported by this class.  These are currently Roles and Session.

=head2 roles

Returns an array of roles associated with this user, if roles are configured for this user class.

=head2 for_session

Returns a serialized user for storage in the session.

=head2 from_session

Revives a serialized user from storage in the session.

=head2 get ( $fieldname )

Returns the value of $fieldname for the user in question.  Roughly translates to a call to
the DBIx::Class::Row's get_column( $fieldname ) routine.

=head2 get_object

Retrieves the DBIx::Class object that corresponds to this user

=head2 obj (method)

Synonym for get_object

=head2 auto_create

This is called when the auto_create_user option is turned on in
Catalyst::Plugin::Authentication and a user matching the authinfo provided is not found.
By default, this will call the C<auto_create()> method of the resultset associated
with this object. It is up to you to implement that method.

=head2 auto_update

This is called when the auto_update_user option is turned on in
Catalyst::Plugin::Authentication. Note that by default the DBIx::Class store
uses every field in the authinfo hash to match the user. This means any
information you provide with the intent to update must be ignored during the
user search process. Otherwise the information will most likely cause the user
record to not be found. To ignore fields in the search process, you
have to add the fields you wish to update to the 'ignore_fields_in_find'
authinfo element.  Alternately, you can use one of the advanced row retrieval
methods (searchargs or resultset).

By default, auto_update will call the C<auto_update()> method of the
DBIx::Class::Row object associated with the user. It is up to you to implement
that method (probably in your schema file)

=head1 BUGS AND LIMITATIONS

None known currently, please email the author if you find any.

=head1 AUTHOR

Jason Kuri (jayk@cpan.org)

=head1 LICENSE

Copyright (c) 2007 the aforementioned authors. All rights
reserved. This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.
