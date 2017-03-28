package user;
use Digest;
use Data::Dumper;
use DBI;


# drop sequence s_users;
# drop table users;
# create sequence s_users;
# create table users (
#     id int unique not null DEFAULT nextval('s_users'), 
#     email text not null unique,
#     name text, 
#     hash text not null
# );
# drop sequence s_mail;
# drop table mail;
# create sequence s_mail;
# create table mail (
#     id int unique not null DEFAULT nextval('s_mail'), 
#     sender text,
#     reciver text,
#     subject text,
#     body text, 
#     status int DEFAULT 0
# );


our $BCRYPT_COOKIE_SALT = "aocr8MDWRjwAiNgn";
our $BCRYPT_SALT = "iRVKRnIBlutucTLu";
our $BCRYPT_COST = 12;

sub __create_recovery_hash {
    srand( time() ^ ($$ + ($$ << 15)) );
    my @v = qw ( a e i o u y );
    my @c = qw ( b c d f g h j k l m n p q r s t v w x z );

    my ($flip, $str) = (0,'');
    $str .= ($flip++ % 2) ? $v[rand(6)] : $c[rand(20)] for 1 .. 19;
    $str =~ s/(....)/$1 . int rand(10)/e;
    $str = uc($str);
    $str =~ s/^(.....)(.....)(.....)(.....)$/$1\-$2\-$3\-$4/;
    return $str;
}

sub send_mail {
    my %argv = @_;

    my $DBH = $argv{dbh};

    my $fields = {
        'reciver' => {
            isemail => 1,
            rusName => 'Получатель',
            isrequired => 1,
        },
        'sender' => {
            isemail => 1,
            rusName => 'Отправитель',
            isrequired => 1,
        },
        'subject' => {
            isemail => 0,
            rusName => 'Тема',
            isrequired => 1,
        },
        'body' => {
            isemail => 0,
            rusName => 'Текст письма',
            isrequired => 1,
        },
    };

    my $error = '';
    foreach my $k (keys %{$fields}) {
        # проверяем обязательнось
        if ( $foreach->{$k}{isrequired} && !$argv->{$k} ) {
            $error .= "Поле \"$fields->{$k}{rusName}\" обязательно, но не заполнено.";
        }
        # проверка на email
        if ( $foreach->{$k}{isemail} && $argv->{$k} =~ /^\w+\@\w+$/ ) {
            $error .= "Поле \"$fields->{$k}{rusName}\" должно быть email-ом.";
        }
    }
    unless ( $error ){
        my $ins = "insert into mail (reciver,sender,subject,body) values (".($DBH->quote($argv{reciver})).",".($DBH->quote($argv{sender})).",".($DBH->quote($argv{subject})).",".($DBH->quote($argv{body})).")";
        $DBH->do($ins);
        if ( $DBH->errstr ) {
            $error .= $DBH->errstr ;
            $DBH->rollback;
        } else {
            $DBH->commit;
        }
    }

    return ( $error ?('Error',$error):('Ok',''));
}

sub check_dig {
    my $dbh = shift;
    my $data = shift;
    my $ret = _make_ret('check_dig');

    my $hash = _get_hash($data->{email},1);

    if ( $hash ne $data->{dig} ) {
        $ret->{status} = 'Error';
        $ret->{status_text} = 'Поддельная кука';
    }

    return $ret;

}


sub check_user {
    my $dbh = shift;
    my $data = shift;
    my $ret = _make_ret('check_user');

    $data->{hash} = _get_hash($data->{hash});

    if ( ($dbh->selectrow_array("select id from users where hash='$data->{hash}' and upper(email)=upper('$data->{email}')"))[0] ) {
        $ret->{email} = $data->{email};
        $ret->{dig} = _get_hash($data->{email},1);        
    } else {
        $ret->{status} = 'Error';
        $ret->{status_text} = 'Неверный email или пароль';        
    }


    return $ret;

}

sub update_user {
    my $dbh = shift;
    my $data = shift;
    my $ret = _make_ret('update_user');
    my $error = '';

    $data->{hash} = _get_hash($data->{hash});

    my $user_id = ($dbh->selectrow_array("select id from users where recovery_hash='$data->{key}'"))[0];

    if ( $user_id ) {
        my $ins = "update users set hash='$data->{hash}',recovery_hash=NULL where id=$user_id";
        $dbh->do($ins);
    } else {
        $error = 'Не найдет пользователь';
    }

    if ( $dbh->errstr || $error) {
        $ret->{status} = 'Error';
        $ret->{status_text} = $dbh->errstr.$error;
        $dbh->rollback;
    } else {
        $ret->{email} = $data->{email};
        $ret->{dig} = _get_hash($data->{email},1);
        $dbh->commit;
    }

    return $ret;

}


sub add_user {
    my $dbh = shift;
    my $data = shift;
    my $ret = _make_ret('add_user');

    $data->{hash} = _get_hash($data->{hash});

    my $ins = "insert into users (".(join(",",(keys %{$data}))).") values ('".(join("','",(values %{$data})))."')";

    $dbh->do($ins);

    if ( $dbh->errstr ) {
        $ret->{status} = 'Error';
        $ret->{status_text} = $dbh->errstr;
        $dbh->rollback;
    } else {
        $ret->{email} = $data->{email};
        $ret->{dig} = _get_hash($data->{email},1);
        $dbh->commit;
    }

    return $ret;

}

sub _make_ret {
    return {status=>'Ok',status_text=>'','call'=>$_[0]};
}

sub _get_hash {
    my $pass = shift;
    my $isForCookie = shift || '';

    my $bcrypt = Digest->new('Bcrypt');
    $bcrypt->cost(_get_cost());
    # $salt must be exactly 16 octets long
    $bcrypt->salt(_get_salt($isForCookie));

    $bcrypt->add($pass);
    return $bcrypt->b64digest;
}

sub _get_salt {
    my $isForCookie = shift;
    return ($isForCookie ? $BCRYPT_COOKIE_SALT : $BCRYPT_SALT);
}

sub _get_cost {
    return $BCRYPT_COST;
}

1;
