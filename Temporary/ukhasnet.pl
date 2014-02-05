#!/usr/bin/perl -w
use strict;
use Time::Local;
use Digest::CRC qw(crcccitt);
use DBI();
use POSIX qw(setsid);
use Sys::Syslog;

# TODO List
# Check SQL inserts/updates work otherwise log an error message and set $error=1 - or $error=1 on ->execute() ??
# Move packet data Processing into sub?
# Get password from command line
# Test Transactions work (i.e. if a query fails we roll it all back) - How to test?
# How to deal with sequence = a
#   Should also not link to previous packets (requires us to remember state)

# Load/cache fieldtypes into hashref

my %Options=(
  db_host     =>"philcrump.co.uk",
  db_database =>"postgres",
  db_user     =>"mike",
  db_pass     =>"m1ari",
  db_type     =>"pg",
  sleep_time  =>3,
  lock_file   =>$ENV{"HOME"} . "/run/ukhasnet.pid"
);

if ( -f $Options{'lock_file'}){
	print "A process is already running\n";
	exit -1;
}
open (_LOCK, ">".$Options{'lock_file'}) or die "Unable to create lockfile\n";
&daemonize;
print _LOCK "$$";
close _LOCK;

my $lastpos=0;
my $loop=1;
my $entries=0;
my $dbh=0;

# Syslog
openlog('ukhasnet', 'cons,pid', 'local1');

$SIG{HUP}= \&catch_hup;
$SIG{INT}= \&catch_hup;

syslog('info', 'Starting');
while ($loop){
	$entries=0;     # Reset Counter
	$dbh = DBI->connect("DBI:Pg:host=$Options{'db_host'};database=$Options{'db_database'}", $Options{'db_user'},$Options{'db_pass'});
	# Check we're connected to the DB
		if ($dbh){
		$dbh->do("SET search_path TO ukhasnet");

		# Prep SQL Statements
		my $getUploads=$dbh->prepare("select id, nodeid, extract(epoch from time) as time, packet from upload where state='Pending' ORDER BY time DESC LIMIT 50");
		my $findPacket=$dbh->prepare("
			select packet.id as packetid from packet left join nodes on packet.originid=nodes.id where
			name=? and sequence=? and checksum=? and to_timestamp(?)
			between
				(select min(packet_rx_time) from packet_rx where packetid=packet.id) - interval '1' minute
			and
				(select max(packet_rx_time) from packet_rx where packetid=packet.id) + interval '1' minute");
		my $addPacket=$dbh->prepare("insert into packet (originid, sequence, checksum) values (?, ?, ?)");
		my $addPacketRX=$dbh->prepare("insert into packet_rx (packetid, gatewayid, packet_rx_time, uploadid) values (?, ?, to_timestamp(?), ?)");
		my $addPath=$dbh->prepare("insert into path (packet_rx_id, position, nodeid) values (?, ?, ?)");
		my $uploadUpdate=$dbh->prepare("update upload set packetid=?, state='Processed' where id=?");
		my $uploadFailed=$dbh->prepare("update upload set state='Error' where id=?");

		# Queries for handling data portion of the packet
		my $getRawData=$dbh->prepare("select id, packetid, data from rawdata where state='Pending' LIMIT 60");
		my $getField=$dbh->prepare("select id, type from fieldtypes where dataid=?");
		my $data_float=$dbh->prepare("insert into data_float (packetid, fieldid, data, position) values (?, ?, ?, ?)");
		# data int
		# data string
		my $data_raw=$dbh->prepare("insert into rawdata (packetid, data, state) values (?, ?, ?)");
		my $dataProcessed=$dbh->prepare('update rawdata set state=$2 where id=$1');
		my $delRaw=$dbh->prepare('delete from rawdata where id=?');

		# Get Pending records from the upload Table
		$getUploads->execute();
		while (my $record=$getUploads->fetchrow_hashref){
			syslog('info', "Processing Packet \"".$record->{'packet'}."\"(".$record->{'id'}.")");
			$entries++;
			if ($record->{'packet'} =~ /^([0-9])([a-z])([A-Z0-9\.,\-]+)\[([A-Za-z0-9,]+)\]\r?$/){
				$dbh->begin_work();	# Start Transaction
				my $error=0;

				#my $repeat=$1;
				my $seq=$2;
				my $data=$3;
				my $path=$4;

				my ($origin,$therest) = split(',', $path);
				my $csum=crcccitt($seq . $data . $origin);

				# See if the packet has already been seen - If not store it.
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
					# Get NodeID for Origin
					my $nodeID=&getNodeID($origin);

					if ($nodeID >0){
						$addPacket->execute($nodeID,$seq,$csum);
						$PacketID=$dbh->last_insert_id(undef, "ukhasnet", "packet", undef);
						# Store the Data portion of the packet in rawdata for later processing
						$data_raw->execute($PacketID, $data, 'Pending');
					} else {
						$error=1;
						print "Error: (addPacket) Unable to get NodeID\n";
					}
				}

				# Store details of this reception of the packet
				if ($PacketID > 0){
					$addPacketRX->execute($PacketID, $record->{'nodeid'}, $record->{'time'},$record->{'id'});
					my $rxID=$dbh->last_insert_id(undef, "ukhasnet", "packet_rx", undef);
					$uploadUpdate->execute($PacketID,$record->{'id'});

					my $hop=0;
					foreach (split(',', $path)){
						my $nodeID=&getNodeID($_);
						if ($nodeID >0){
							$addPath->execute($rxID, $hop++, $nodeID);
						} else {
							$error=1;
							syslog('warning', "Error: (addPath) Unable to get NodeID($PacketID:$rxID)");
						}
					}
				}
				if ($error == 0){
					$dbh->commit();
				} else {
					# Rollback
					$dbh->rollback();
					$uploadFailed->execute($record->{'id'});
					die "DB Transaction failed\n";
				}
			} else {
				# Unknown packet format
				print "?> ".$record->{'packet'}."(".$record->{'id'}.")\n";
				$uploadFailed->execute($record->{'id'});
			}
		} #while (my $record=$getUploads->fetchrow_hashref){


		# Process the data in rawdata
		$getRawData->execute();
		while (my $datarow=$getRawData->fetchrow_hashref){
			$dbh->begin_work();	# Start Transaction
			my $error=0;

			my $data=$datarow->{'data'};

			# Process packet data
			while ($data) {
				syslog('info', "Processing Data \"$data(".$datarow->{'id'}.")");
				my ($var, $val);
				($var, $val, $data) = &splitData($data);
				if ($var =~ /[A-Z]/){
					$getField->execute($var);
					if ($getField->rows()==1){
						my $type=$getField->fetchrow_hashref;
						if ($type->{'type'} eq "Float"){ 
							my $p=0;
							foreach my $v (split(/,/, $val)){
								$data_float->execute($datarow->{'packetid'}, $type->{'id'}, $v, $p++);
							}
						} elsif ($type->{'type'} eq "Integer"){
							syslog('warning', "Error: Cant store ".$type->{'type'}." for ".$var.$val."($datarow->{'packetid'})");
							$data_raw->execute($datarow->{'packetid'}, $var.$val, 'Error');
						} elsif ($type->{'type'} eq "String"){
							syslog('warning', "Error: Cant store ".$type->{'type'}." for ".$var.$val."($datarow->{'packetid'})");
							$data_raw->execute($datarow->{'packetid'}, $var.$val, 'Error');
						} else {
							syslog('warning', "Error: Unknown type(".$type->{'type'}.") for ".$var.$val."($datarow->{'packetid'})");
							$data_raw->execute($datarow->{'packetid'}, $var.$val, 'Error');
						}
					} else {
						syslog('warning', "Error: Wrong number of rows for ".$var.$val."($datarow->{'packetid'})");
						$data_raw->execute($datarow->{'packetid'}, $var.$val, 'Error');
					}
				} else {
					syslog('warning', "Error: Cannot process $data($datarow->{'packetid'})");
					$data_raw->execute($datarow->{'packetid'}, $data, 'Error');
					undef($data);
				}
			} # while($data)
			#$dataProcessed->execute($datarow->{'id'}, 'Processed');
			$delRaw->execute($datarow->{'id'});
			if ($error == 0){
				$dbh->commit();
			} else {
				# Rollback
				$dbh->rollback();
				$dataProcessed->execute($datarow->{'id'}, 'Error');
				die "DB Transaction failed\n";
			}
		} # while($datarow


		# Close SQL Connections
		$getUploads->finish();
		$findPacket->finish();
		$addPacket->finish();
		$addPacketRX->finish();
		$addPath->finish();
		$uploadUpdate->finish();
		$uploadFailed->finish();
		$getRawData->finish();
		$getField->finish();
		$data_float->finish();
		$data_raw->finish();
		$dataProcessed->finish();
		$delRaw->finish();
		$dbh->disconnect();
		sleep (20) if ($loop && ($entries==0));
	} else { #if ($dbh)
		syslog('warning', "Error: Unable to connect to DB");
		sleep(60) if $loop;
	}
} #while($loop)

unlink $Options{'lock_file'};
syslog('info', 'Finished');

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

sub getNodeID {
	die "Wrong number of args to getNodeID\n" if (scalar(@_) !=1 );
	my $origin=$_[0];
	my $nodeID=0;

	my $getNode=$dbh->prepare("select id from nodes where name = ?");
	my $addNode=$dbh->prepare("insert into nodes (name) values (?)");
	$getNode->execute($origin);
	if ($getNode->rows()==1){
		my $nodeRow=$getNode->fetchrow_hashref;
		$nodeID=$nodeRow->{'id'};
	} elsif ($getNode->rows()>1){
		print "Error: Matched more than one node\n"; #Input line ".$record->{'packet'}."(".$record->{'id'}.") matches more than one origin node in DB\n";
		while (my $nodeRow=$getNode->fetchrow_hashref){
			print "-->Potential ID " . $nodeRow->{'id'} . "\n";
		}
	} else {
		$addNode->execute($origin);
		$nodeID=$dbh->last_insert_id(undef, "ukhasnet", "nodes", undef);
		print "--> Added Node $origin($nodeID)\n";
	}
	#$getNode->finish();
	#$addNode->finish();
	return $nodeID;
}

sub splitData {
	die "Wrong number of args to getNodeID\n" if (scalar(@_) !=1 );
	my $data=$_[0];
	if ($data =~ /^([A-Z])([0-9\.,\-]+)(.*)$/ ){
		return ($1, $2, $3);
	} else {
		print "Error: No Match for $data\n";
		return (-1,-1,$data);
	}
}
