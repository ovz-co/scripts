#!/usr/bin/perl -w

# AUTHOR  : ~RSS
# CMD     : taild.pl
# VERSION : 0.0.10 / 2013.06.29
# COMMENT : Мониторинг логов по ключевым словам

# Сброс буфера вывода после каждой операции вывода.
$|=1;

use strict;
use threads;
use Thread::Queue;
use POSIX;

sub gettime();
sub llog($ $);
sub daemonize();
sub taild($);


my %config = (
    global => {
        debug       => 0,
        log_console => 100,
        log_level   => 1,
        log_file    => '/var/log/taild.log',
        block_add   => '<cmd action> %str%',
        block_del   => '<cmd action> %str%',
        block_ban   => '<cmd action> %str%',
        block_time  => 3600,
        block_count => 2,
        weight      => 1,
        max_count   => 2000,
        max_items   => 1000
    },
    services => {
        httpd => {
            file         => '/var/log/apache.log',
            regex_search => 'GET administrator/index.php',
            regex_data   => '^(.+)?\s.*',
            max_count    => 500,
            weight       => 1,
            block_time   => 1200,
            message      => 'Bruteforce joomla Administrator'
        },
        sshd => {
            file         => '/var/log/sshd.log',
            regex_search => 'Illegal user.*?\sfrom',
            regex_data   => 'from\s(.*)?\,',
            max_count    => 30,
            weight       => 10,
            message      => 'Bruteforce SSH user'
        }
    }
);

my $qmsg = Thread::Queue->new;
my %hashdb;

daemonize() if (!defined($config{'global'}{'debug'}) || $config{'global'}{'debug'} == 0);

$SIG{HUP} = sub {
      %hashdb = {};
      print "list nulled\n";
};
$SIG{USR1} = sub {
      print "got SIGUSR1\n";
};
$SIG{USR2} = sub {
      print "got SIGUSR2\n";
};
llog(0,"Program started pid:[$$]");

foreach my $service (keys %{ $config{'services'} }) {
    threads->new(\&taild, $service)->detach;
}

while (1) {
    if (defined(my $message = $qmsg->dequeue())) {
        my @data = split(/;/, $message);
        print "SID: $data[0] $data[2]\n";
    }
}

#--# SUBs

sub daemonize() {
    chdir '/'                  or llog(99,"Can't chdir to /: $!");
    open STDIN, '/dev/null'    or llog(99,"Can't read /dev/null: $!");
    open STDOUT, '>>/dev/null' or llog(99,"Can't write to /dev/null: $!");
    open STDERR, '>>/dev/null' or llog(99,"Can't write to /dev/null: $!");
    defined(my $pid = fork)    or llog(99,"Can't fork: $!");
    exit if $pid;
    setsid()                   or llog(99,"Can't start a new session: $!");
    umask 0;
}

sub gettime() {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
    my $fmttime = sprintf ( "[%04d-%02d-%02d %02d:%02d:%02d]",
                            $year+1900,$mon+1,$mday,$hour,$min,$sec);
    return $fmttime;
}

sub llog($ $) {
    my $llevel = shift;
    my %elevel = (0=>"debug", 1=>"notice", 2=>"warning", 3=>"error", 98=>"stat", 99=>"die");
    my $lmsg = shift;
    if ($config{'global'}{'log_console'} !~ "null" && $llevel >= $config{'global'}{'log_console'}) {
        print gettime()." [$elevel{$llevel}] $lmsg\n";
    }
    if ($config{'global'}{'log_file'} !~ "null" && $llevel >= $config{'global'}{'log_level'}) {
        open PRGLOG, ">>$config{'global'}{'log_file'}" or die "Can not open $config{'global'}{'log_file'} for writing: $!";
          print PRGLOG gettime()." [$elevel{$llevel}] $lmsg\n";
        close PRGLOG;
    }
    exit if ($llevel == 99);
}

sub taild($) {
    my $sid = shift;
    my (@extract, $t_weight, $t_file, $t_regex_s, $t_regex_d);
    $t_weight = (defined($config{'services'}{$sid}{'weight'})) ? $config{'services'}{$sid}{'weight'} : $config{'global'}{'weight'};
    $t_file = $config{'services'}{$sid}{'file'} or llog(99, "Empty filename! [$sid]");
    $t_regex_s = $config{'services'}{$sid}{'regex_search'} or llog(99, "Empty regex for search! [$sid]");
    $t_regex_d = $config{'services'}{$sid}{'regex_data'} or llog(99, "Empty regex for extract data! [$sid]");
    
    # Пробуем открыть файл на чтение
    open LOG, "<$t_file" or llog(99,"Could not open $t_file for reading:[$!]");
    # Ищем конец файла
    seek LOG, 0, 2;
    while (1) {
        sleep 1;
        # re-seek to current position
        seek LOG, 0, 1;
        my $pos = tell(LOG);
        # Смотрим размер файла
        my $size = -s $t_file;
        # Если отработал logrotate - переоткрываем файл
        if ($size < $pos) {
            close LOG;
            open LOG, "<$t_file" or llog(99,"Could not open $t_file for reading:[$!]");
            llog(0,"Logfile $t_file reopened");
        }
        while (<LOG>) {
            next unless /$t_regex_s/;
            chomp $_;
            @extract = ( $_ =~ m/$t_regex_d/ );
            $qmsg->enqueue("$sid;$t_weight;$extract[0]");
            $qmsg->enqueue(undef);
        }
    }
}
