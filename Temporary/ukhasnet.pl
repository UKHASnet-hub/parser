#!/usr/bin/perl -w
use strict;
use LWP::Simple;
#use POSIX;
use Time::Local;
use Digest::CRC qw(crcccitt);
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
        my $dbh = DBI->connect("DBI:mysql:host=$Options{'db_host'};database=$Options{'db_database'}", $Options{'db_user'},$Options{'db_pass'});

        # Check we're connected to the DB
        if ($dbh){
                # Prep SQL Statements
		#my $findPacket=$dbh->prepare("select distinct packet.id as packetid from packet left join packet_rx on packet.id=packet_rx.packetid where origin=? and sequence=? and checksum = ?");
			# TODO Add time check
			# time between min - 15s and max +15s
			my $findPacket=$dbh->prepare("
				select packet.id as packetid from packet where 
				origin= ? and sequence= ? and checksum = ? and from_unixtime(?)
				between 
					date_sub((select min(packet_rx_time) from packet_rx where packetid=packet.id), interval 1 minute)
				and
					date_add((select max(packet_rx_time) from packet_rx where packetid=packet.id), interval 1 minute)");
		my $addPacket=$dbh->prepare("insert into packet (origin, sequence, checksum) values (?, ?, ?)");
		my $addPacketRX=$dbh->prepare("insert into packet_rx (packetid, gateway, packet_rx_time) values (?, ?, from_unixtime(?))");
		my $addRawPacket=$dbh->prepare("insert into raw_packet (packet_rx_id, data) values (?, ?)");

		my $data=get($Options{'data_url'});

		# TODO Need to skip lines we've already processed
		# select max(time) from packet_rx where gw=JC

		my $inline=0;
		foreach (split('\n',$data)){
			my $packet=$_;
			$inline++;

			if (/^(.*)?[rt]x: ([0-9])([a-z])([A-Z0-9\.,\-]+)\[([A-Z,]+)\]/){			# jcoxon Dump format
				my $time=0;
				if (defined($1)){
					if ($1 =~ /^([0-9]+):-/){						# Time in Unixtime
						$time=$1;
					} elsif ($1 =~ /^([0-9]+-[0-9]+-[0-9]+) ([0-9]+:[0-9]+:[0-9]+):-/){	# Time in YYYY-MM-DD HH:MM:SS
						my ($y,$m,$d) = split('-',$1);
						my ($h,$min,$s) = split(':',$2);
						$time=timegm($s, $min, $h, $d, $m-1, $y);
					} else {								# No Time set
						$time = 1389396784 if ($inline <= 20 );
					}
				}
				my $repeat=$2;
				my $seq=$3;
				my $data=$4;
				my $path=$5;
				my $gw="JC";
				my ($origin,$therest) = split(',', $path);

				my $csum=crcccitt($seq . $data . $origin);

				print "1> $_\n";
				print "\t$time\t$2\t$3\t$4($csum)\t$5\n";

				
				# TODO Check if we have a recently matching packet
				my $PacketID=0;
				#$findPacket->execute($origin, $seq, $csum);
				$findPacket->execute($origin, $seq, $csum, $time);
				if ($findPacket->rows()==1){				# Single Match - GOOD
					my $row=$findPacket->fetchrow_hashref;
					$PacketID=$row->{'packetid'};


					# TODO Process packet data

					# Packet Data
				} elsif ($findPacket->rows()>1){			# Multiple Matches - Bad
					print "Error: Input line $packet matches more than one packet in DB\n";
					while (my $row=$findPacket->fetchrow_hashref){
						print "-->Potential ID " . $row->{'packetid'} . "\n";
					}
				} else {
					$addPacket->execute($origin,$seq,$csum);
					$PacketID=$addPacket->{mysql_insertid};
				}

				if ($PacketID > 0){
					$addPacketRX->execute($PacketID, $gw, $time);	## TODO Need to convert time
					my $rxID=$addPacketRX->{mysql_insertid};
					$addRawPacket->execute($rxID,$packet);
					# Path
				}

				#last if ($inline >=5);
			} elsif (/^(.*)?[rt]x: $/) { 			# jcoxon Dump format
				# Surpress blank lines
			} elsif (/^(.*)?Stop$/) {			# jcoxon Dump format
				# Surpress blank lines
			} else {
				print "?> $_\n";
			}

			# If previous sequence from this node was A ignore any other sequenct
			# Search for packet in DB
			# Sequence of A signifies a reboot - do something different ?
			# If not found add packet

		}


		# Close SQL Connections
		$findPacket->finish();
		$addPacket->finish();
		$addPacketRX->finish();
		$addRawPacket->finish();
                $dbh->disconnect();
		$loop=0;
		print "Done\n";
		#sleep (10);
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

