#!/usr/bin/perl -C 32
use utf8;
use strict;
use Plack;
use Plack::Request;
use Plack::Builder;
use Data::Dumper;
use JSON;   
use DBI;
use FindBin;
use CGI qw/:standard -utf8/;
use URI::Escape;
use POSIX qw(locale_h);
setlocale(LC_CTYPE, "ru_RU.UTF-8");
use Text::Iconv;
use Digest;
use Encode;

use lib "$FindBin::Bin/lib";
use bilet;
use user;

our $ret_build_tree;
# my $conffile = __FILE__; $conffile =~ s/psgi\/api.pl/config\.txt/;
# my $conf = {};#CONF->new("filename"=>$conffile);

my $routing = {
    "api" => {
        "curs"  => \&_get_curs,
        "user"  => \&_u,
        "check_cookie" => \&_check_cookie,
        "remember" => \&_remember,
    },
};

my $dbh = DBI->connect("DBI:Pg:dbname=bilet","bilet","qasw123",{AutoCommit=>0, pg_enable_utf8=>1});
END{$dbh->disconnect;};

########################
#
#   Core functions
#
########################

my $api_hash = sub {
    my $env = shift;
    my ($f,$sn) = PathFinding($env->{SCRIPT_NAME}.$env->{PATH_INFO},$routing);
    $env = _new_data_for_env($env,$sn);
    return Call($f,'hash',$env);    
};


sub _new_data_for_env {
    my ($env,$sn) = @_;
    my $u = $env->{SCRIPT_NAME}.$env->{PATH_INFO}."/";
    $u =~ s/$sn//;
    $env->{SCRIPT_NAME} = $sn;
    $env->{PATH_INFO} = $u;
    return $env;
}

sub PathFinding{
    my $p = shift; $p =~ s/^\///; $p =~ s/\/$//;
    my $r = shift;
    my @path =  split "/",$p;

    my $sn = [];

    foreach my $k (@path) {
        $r = $r->{$k};    
        push @{$sn},$k;
        if (ref $r eq 'CODE'){
            last;
        }
    }
    if (ref $r eq 'HASH'){
        return ('','');
    }else{
        return ($r,("/".(join("/",@{$sn}))));
    }
}

sub Call {
    my $func = shift;
    my $return_type = shift;
    my $env = shift;

    my ($db,$req,$res,$cookies,$data,$begin_error);
    my $req = Plack::Request->new($env);
    my $res = $req->new_response(200);
    $res->header('Content-Type' => "application/json", charset => 'UTF-8');

    if ($req->{env}{REQUEST_METHOD} eq 'GET'){
      $data = $req->{env}{QUERY_STRING};$data = uri_unescape($data);
    }else{
      $req->{env}{'psgi.input'}->read($data,$req->{CONTENT_LENGTH}); 
    }

    $data = "{}" unless ($data);

    $data = decode_utf8( $data );
    $data = from_json($data);

    my ($body,$error)  = $func->($dbh,$req,$res,$cookies,$data,$begin_error);

    if ($error){
        $res = onError($req,$error);
    }else{
        $res->body ( to_json( $body ));
    }
    
    # $dbh->disconnect;
    return $res->finalize();
}

sub onError {
    my $req = shift;
    my $error = shift;

    my $res = $req->new_response(502);
    $res->header('Content-Type' => 'application/json', charset => 'UTF-8');
    $res->content_type('application/json');        
    $res->body(to_json({'status'=>'Error','text'=>$error}));

    return $res;
}

######################
#
#  Курс
#
######################

sub _get_curs{
    my ($dbh,$req,$res,$cookies,$data,$begin_error) = @_;

    my $s = user::__create_recovery_hash();

    return ({"recovery_hash"=>$s});

    # my $bcrypt = Digest->new('Bcrypt');
    # # my $cost = ;
    # $bcrypt->cost(10);
    # # $salt must be exactly 16 octets long
    # $bcrypt->salt('1327112213271122');

    # $bcrypt->add("qasw123");
    # my $d = $bcrypt->b64digest;
    # return ({"bcrypt"=>$d,"curs" => "CURS", "ecurs" => ($dbh->selectrow_array("select name from test where id=1"))[0]},'');
    # return ({"curs" => $data->{"curs"}, "ecurs" => $data->{"ecurs"}},'');
}

sub _u {
    my ($dbh,$req,$res,$cookies,$data,$begin_error) = @_;

    my $ret = {};
    my $error = '';

    if ( $req->method eq 'POST' ) {
        # новый юзер
        my $user_data = {
            "email"=>$data->{UserEmail},
            "hash"=>$data->{UserPassword},
        };
        $ret = user::add_user($dbh, $user_data);
        if ( $ret->{status} ne 'Ok' ) {
            $error .= $ret->{status_text};
        }        
    } elsif( $req->method eq 'UPDATE' ) {
        # логин
        my $user_data = {
            "key"=>$data->{UserKey},
            "hash"=>$data->{UserPassword},
        };
        $ret = user::update_user($dbh, $user_data);
        if ( $ret->{status} ne 'Ok' ) {
            $error .= $ret->{status_text};
        }        
    } elsif( $req->method eq 'GET' ) {
        # логин
        my $user_data = {
            "email"=>$data->{UserEmail},
            "hash"=>$data->{UserPassword},
        };
        $ret = user::check_user($dbh, $user_data);
        if ( $ret->{status} ne 'Ok' ) {
            $error .= $ret->{status_text};
        }        
    } elsif( $req->method eq 'PUT' ) {
        # проверка куки
        my $user_data = {
            "email"=>$data->{email},
            "dig"=>$data->{dig},
        };
        $ret = user::check_dig($dbh, $user_data);
        if ( $ret->{status} ne 'Ok' ) {
            $error .= $ret->{status_text};
        }        


    } else {
        $error = 'This is not POST';
    }

    return($ret,$error);    

}

sub _remember {
    my ($dbh,$req,$res,$cookies,$data,$begin_error) = @_;
    warn('call _remember');
    warn(Dumper($data));
    warn($dbh);

    my $ret = {'status'=>'Ok'};
    my $error = '';

    my $recovery_hash = user::__create_recovery_hash();

    my $user_id = ($dbh->selectrow_array("select id from users where email=?",undef,$data->{eml}))[0];
    warn("user_id=$user_id");

    if ( $user_id ){
        $dbh->do("update users set recovery_hash=? where id=?",undef,($recovery_hash,$user_id));
        ($ret->{status},$error) = user::send_mail(
            "dbh" => $dbh,
            "sender" => 'info@bilet.nikonor.ru',
            'reciver' => $data->{eml},
            'subject' => 'Восстановление пароля для сайта bilet.nikonor.ru',
            'body' => 'Для изменения паролья пройте по ссылке: http://bilet.nikonor.ru/?'.$recovery_hash
        );
    } else {
        $ret->{status} = 'Error';
        $error = "не найдет такой адрес";
    }

    return($ret,$error);        
}


sub _check_cookie {
    my ($dbh,$req,$res,$cookies,$data,$begin_error) = @_;

    my $ret = {'status'=>'Ok'};
    my $error = '';


    return($ret,$error);    
}


my $main_app = builder {
    mount "/api" => builder { $api_hash; };
};
