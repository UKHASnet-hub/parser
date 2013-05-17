#!/usr/bin/perl -w
use strict;
use LWP::Simple;
use DBI();
use POSIX qw(setsid);
use Sys::Syslog qw(:DEFAULT setlogsock);

my %Options=(
  db_host     =>"db1.private.yapd.net",
  db_database =>"ukhasnet",
  db_user     =>"ukhasnet",
  db_pass     =>"",
  data_url    =>"http://jcoxon.no-ip.org/data.txt",
  sleep_time  =>3,
  lock_file   =>$ENV{"HOME"} . "/run/ukhasnet.pid"
);

if  ( -f $Options{'lock_file'}){
        print "A process is already running\n";
        exit -1;
}
#open (_LOCK, ">".$Options{'lock_file'}) or die "Unable to create lockfile\n";
#&daemonize;
#print _LOCK "$$";
#close _LOCK;

my $lastpos=0;
my $loop=1;
my $entries=0;

# Syslog
setlogsock('unix');
openlog('ukhasnet', 'cons,pid', 'local1');

#$SIG{HUP}= \&catch_hup;
#$SIG{INT}= \&catch_hup;

syslog('info', 'Starting');
while ($loop){
        $entries=0;     # Reset Counter
#        my $dbh = DBI->connect("DBI:mysql:host=$Options{'db_host'};database=$Options{'db_database'}", $Options{'db_user'},$Options{'db_pass'});
	my $dbh=1;

        # Check we're connected to the DB
        if ($dbh){

                # Prep SQL Statements
                #my $addPosition=$dbh->prepare("insert into positions values (?,?,?,?,MICROSECOND(?)/1e6,?,MICROSECOND(?)/1e6,?,?,?,?,?,?,?,?)");
                #my $addCall=$dbh->prepare("insert into positions_call values (?,?)");
                #my $addData=$dbh->prepare("insert into positions_data values (?,?,?)");

		my $data=get($Options{'data_url'});
		foreach (split('\n',$data)){

			if (/^([0-9]+:- )?[rt]x: ([0-9])([a-z])([A-Z0-9\.,\-]+)\[([A-Z,]+)\]/){ #L51.5,-0.05T0000\[([A-Z,]+)\]$/){
				my $time=0;
				if (defined($1)){
					if ($1 =~ /([0-9]+):-/){
						$time=$1;
					}
				}
				print "1> $_\n";
				print "\t$time\t$2\t$3\t$4\t$5\n";
			} else {
				print "?> $_\n";
			}
#
		}


                #$addPosition->finish();
                #$addCall->finish();
                #$addData->finish();
                #$dbh->disconnect();
		print "Done\n";
		sleep (10);
        } else { #if ($dbh)
                sleep(60) if $loop;
        }

        sleep($Options{'sleep_time'});
} #while($loop)

unlink $Options{'lock_file'};

sub daemonize {
        chdir '/'                 or die "Can't chdir to /: $!";
        defined(my $pid = fork)   or die "Can't fork: $!";
        exit if $pid;
        setsid                    or die "Can't start a new session: $!";
        umask 0;
}

sub catch_hup {
        $loop=0;
        syslog('warning', 'Got HUP');
}

