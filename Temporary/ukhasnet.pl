#!/usr/bin/perl -w
use strict;
use Time::Local;
use Digest::CRC qw(crcccitt);
use DBI();
use POSIX qw(setsid);
use Sys::Syslog qw(:DEFAULT setlogsock);

# TODO List
# Test Transactions work (i.e. if a query fails we roll it all back) - How to test?
# Path table links to nodes rather than storing the path values.
# Store data from the packets into the DB
# Log to syslog instead of console
# How to deal with sequence = a
#   Should also not link to previous packets (requires us to remember state)
# Get password from command line

my %Options=(
  db_host     =>"philcrump.co.uk",
  db_database =>"postgres",
  db_user     =>"mike",
  db_pass     =>"****",
  db_type     =>"pg",
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

$SIG{HUP}= \&catch_hup;
$SIG{INT}= \&catch_hup;

syslog('info', 'Starting');
while ($loop){
        $entries=0;     # Reset Counter
	print "Connecting to DB...";
	my $dbh = DBI->connect("DBI:Pg:host=$Options{'db_host'};database=$Options{'db_database'}", $Options{'db_user'},$Options{'db_pass'});
	$dbh->do("SET search_path TO ukhasnet, public") if ($Options{'db_type'} eq "pg");
	print "Connected\n";

        # Check we're connected to the DB
        if ($dbh){
                # Prep SQL Statements
		my $getData=$dbh->prepare("select id, nodeid, extract(epoch from time) as time, packet from ukhasnet.upload where state='Pending' limit 50");
		my $findPacket=$dbh->prepare("
			select packet.id as packetid from packet where
			origin=? and sequence=? and checksum=? and to_timestamp(?)
			between
				(select min(packet_rx_time) from packet_rx where packetid=packet.id) - interval '1' minute
			and
				(select max(packet_rx_time) from packet_rx where packetid=packet.id) + interval '1' minute");
		my $addPacket=$dbh->prepare("insert into packet (origin, originid, sequence, checksum) values (?, ?, ?, ?)");
		my $addPacketRX=$dbh->prepare("insert into packet_rx (packetid, gatewayid, packet_rx_time, uploadid) values (?, ?, to_timestamp(?), ?)");
		my $addPath=$dbh->prepare("insert into path (packet_rx_id, position, node) values (?, ?, ?)");
		my $uploadUpdate=$dbh->prepare("update upload set packetid=?, state='Processed' where id=?");
		my $uploadFailed=$dbh->prepare("update upload set state='Error' where id=?");

		my $getNode=$dbh->prepare("select id from nodes where name = ?");
		my $addNode=$dbh->prepare("insert into nodes (name) values (?)");

		$getData->execute();
		while (my $record=$getData->fetchrow_hashref){

			$entries++;
			print ">".$record->{'packet'}."\t(".$record->{'id'}.")\t".$record->{'time'}."\n";
			if ($record->{'packet'} =~ /^([0-9])([a-z])([A-Z0-9\.,\-]+)\[([A-Za-z,]+)\]\r?$/){
				$dbh->begin_work();	# Start Transaction
				my $error=0;

				#my $repeat=$1;
				my $seq=$2;
				my $data=$3;
				my $path=$4;

				my ($origin,$therest) = split(',', $path);
				my $csum=crcccitt($seq . $data . $origin);

				print "->".$record->{'packet'}."\t(".$record->{'time'}.")\t$seq\t$data\t$origin($csum)\t$path\n";

				my $PacketID=0;
				$findPacket->execute($origin, $seq, $csum, $record->{'time'});
				if ($findPacket->rows()==1){				# Single Match - GOOD
					my $row=$findPacket->fetchrow_hashref;
					$PacketID=$row->{'packetid'};
				} elsif ($findPacket->rows()>1){			# Multiple Matches - Bad
					$error=1;
					print "Error: Input line ".$record->{'packet'}."(".$record->{'id'}.") matches more than one packet in DB\n";
					while (my $row=$findPacket->fetchrow_hashref){
						print "-->Potential ID " . $row->{'packetid'} . "\n";
					}
				} else {
					## Get NodeID for Origin
					my $nodeID=0;
					$getNode->execute($origin);
					if ($getNode->rows()==1){
						my $nodeRow=$getNode->fetchrow_hashref;
						$nodeID=$nodeRow->{'id'};
					} elsif ($getNode->rows()>1){
						$error=1;
						print "Error: Input line ".$record->{'packet'}."(".$record->{'id'}.") matches more than one origin node in DB\n";
						while (my $nodeRow=$getNode->fetchrow_hashref){
							print "-->Potential ID " . $nodeRow->{'id'} . "\n";
						}
					} else {
						$addNode->execute($origin);
						$nodeID=$dbh->last_insert_id(undef, "ukhasnet", "nodes", undef);
						print "--> Adding Node $origin($nodeID)\n";
					}
						
					if ($nodeID >0){
						$addPacket->execute($origin,$nodeID,$seq,$csum);
						$PacketID=$dbh->last_insert_id(undef, "ukhasnet", "packet", undef);
						# TODO Process packet data
					}

				}

				if ($PacketID > 0){
					$addPacketRX->execute($PacketID, $record->{'nodeid'}, $record->{'time'},$record->{'id'});
					my $rxID=$dbh->last_insert_id(undef, "ukhasnet", "packet_rx", undef);
					$uploadUpdate->execute($PacketID,$record->{'id'});

					my $hop=0;
					foreach (split(',', $path)){
						$addPath->execute($rxID, $hop++, $_);
					}
				}
				if ($error == 0){
					$dbh->commit();
				} else {
					# Rollback
					die "DB Transaction failed\n";
					$dbh->rollback();
					$uploadFailed->execute($record->{'id'});
				}
			} else {
				print "?> ".$record->{'packet'}."(".$record->{'id'}.")\n";
				$uploadFailed->execute($record->{'id'});
			}


		}

		# Close SQL Connections
		$getData->finish();
		$findPacket->finish();
		$addPacket->finish();
		$addPacketRX->finish();
		$addPath->finish();
		$uploadUpdate->finish();
		$uploadFailed->finish();
		$getNode->finish();
		$addNode->finish();
		$dbh->disconnect();
		print "Done\n";
		sleep (60) if ($loop && ($entries==0));
		sleep (10) if $loop;
        } else { #if ($dbh)
		print "DB connection failed\n";
                sleep(60) if $loop;
        }
	print "Loop done";
        #sleep($Options{'sleep_time'});
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
	print "Got HUP\n";
}

