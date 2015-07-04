#!/usr/bin/perl -w
use strict;
use Time::Local;
use Digest::CRC qw(crcccitt);
use DBI();
use POSIX qw(setsid);
use Sys::Syslog;
use JSON::XS qw( decode_json);

# TODO List
# Check SQL inserts/updates work otherwise log an error message and set $error=1 - or $error=1 on ->execute() ??
# Move packet data Processing into sub?
# Test Transactions work (i.e. if a query fails we roll it all back) - How to test?
# How to deal with sequence = a
#   Should also not link to previous packets (requires us to remember state)

# Load/cache fieldtypes into hashref

# Load Configuration from config.json
my $config;
if ( -f 'config.json' ){
	open(_CONF, "<", "config.json");
	my $config_raw=do { local $/=undef; <_CONF>};
	close(_CONF);
	$config=decode_json($config_raw);
} else {
	die "config.json is not present - you need to create it\n";
}

# TODO Test that config.json has the required values for us to run
# TODO We should probably check it's safe to eval the value here...
my $lock_file=eval($config->{'lock_file'});

if ( -f $lock_file){
	print "A process is already running\n";
	exit -1;
}
open (_LOCK, ">", $lock_file) or die "Unable to create lockfile\n";
&daemonize;
print _LOCK "$$";
close _LOCK;

my $lastpos=0;
my $loop=1;
my $entries=0;
my $dbh=0;

# Syslog
openlog('ukhasnet', 'cons,pid', $config->{'syslog'}{'facility'});

$SIG{HUP}= \&catch_hup;
$SIG{INT}= \&catch_hup;

syslog('info', 'Starting');
while ($loop){
	$entries=0;     # Reset Counter
	$dbh = DBI->connect("DBI:Pg:host=$config->{'database'}{'host'};database=$config->{'database'}{'database'}", $config->{'database'}{'user'},$config->{'database'}{'password'});
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
		my $nodeLastPacket=$dbh->prepare("update nodes set lastpacket=? where id=?");
		my $addPacketRX=$dbh->prepare("insert into packet_rx (packetid, gatewayid, packet_rx_time, uploadid) values (?, ?, to_timestamp(?), ?)");
		my $addPath=$dbh->prepare("insert into path (packet_rx_id, position, nodeid) values (?, ?, ?)");
		my $uploadUpdate=$dbh->prepare("update upload set packetid=?, state='Processed' where id=?");
		my $uploadFailed=$dbh->prepare("update upload set state='Error' where id=?");

		# Queries for handling data portion of the packet
		my $getRawData=$dbh->prepare("select id, packetid, data from rawdata where state='Pending' LIMIT 60");
		my $getField=$dbh->prepare("select id, type from fieldtypes where dataid=?");	# TODO Can we cache this ???
		my $getNodeFromPacket=$dbh->prepare("select originid from ukhasnet.packet where id=?");
		my $data_float=$dbh->prepare("insert into data_float (packetid, fieldid, data, position) values (?, ?, ?, ?)");
		my $data_location=$dbh->prepare("insert into data_location (packetid, latitude, longitude, altitude) values (?, ?, ?, ?)");
		my $updateNodeLocation=$dbh->prepare('update nodes set locationid=$2 where id=$1');
		# data int
		# data string
		my $data_raw=$dbh->prepare("insert into rawdata (packetid, data, state) values (?, ?, ?)");
		my $dataProcessed=$dbh->prepare('update rawdata set state=$2 where id=$1');
		my $delRaw=$dbh->prepare('delete from rawdata where id=?');

		# Notify for websockets
		my $notify=$dbh->prepare('NOTIFY upload_parse, \'{"i": ?,"s":? }\'');

		# Get Pending records from the upload Table
		$getUploads->execute();
		while (my $record=$getUploads->fetchrow_hashref){
			syslog('info', "Processing Packet \"".$record->{'packet'}."\"(".$record->{'id'}.")");
			$entries++;
			if ($record->{'packet'} =~ /^\r?([0-9])([a-z])([A-Z0-9\.,\-]+)(.*)\[([A-Za-z0-9,]+)\]\r?$/){
				$dbh->begin_work();	# Start Transaction
				my $error=0;

				#my $repeat=$1;
				my $seq=$2;
				my $data=$3;
				my $text=$4;
				my $path=$5;

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
					syslog('warning', "Error: Input line ".$record->{'packet'}."(".$record->{'id'}.") matches more than one packet in DB");
					while (my $row=$findPacket->fetchrow_hashref){
						syslog('warning', "Info: Upload ".$record->{'id'}." Potentially matches packet:" . $row->{'packetid'});
					}
				} else {
					# Get NodeID for Origin
					my $nodeID=&getNodeID($origin);

					if ($nodeID >0){
						$addPacket->execute($nodeID,$seq,$csum);
						$PacketID=$dbh->last_insert_id(undef, "ukhasnet", "packet", undef);
						# Store the Data portion of the packet in rawdata for later processing
						$data_raw->execute($PacketID, $data, 'Pending');
						$data_raw->execute($PacketID, $text, 'Error');

						# Update the nodes table to set the last packet value
						$nodeLastPacket->execute($PacketID, $nodeID);
					} else {
						$error=1;
						syslog('warning', "Error: (addPacket) Unable to get NodeID");
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
					#$notify->execute($record->{'id'},"Processed");
					$dbh->do("NOTIFY upload_parse, '{\"i\": ".$record->{'id'}.",\"s\": \"Processed\"}'");
					# NOTIFY upload_parse, '{"i":<uploadid>,"s":"Processed"}';
				} else {
					# Rollback
					$dbh->rollback();
					$uploadFailed->execute($record->{'id'});
					syslog("warning", "Error: DB Transaction failed for upload: ".$record->{'id'});
					#die "DB Transaction failed\n";
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
								# "T-00.-H59(13407566)
								#if ($v =~ /^[+-]?[0-9]+\.?[0-9]*$/){
								if ($v =~ /^[-]?\d+(?:[.]\d+)?$/){
									$data_float->execute($datarow->{'packetid'}, $type->{'id'}, $v, $p++);
								} else {
									syslog('warning', "Error processing type ".$type->{'id'}." with value $v (".$datarow->{'packetid'}.")");
									$data_raw->execute($datarow->{'packetid'}, $var.$val, 'Error');
								}
							}
						} elsif ($type->{'type'} eq "Integer"){
							syslog('warning', "Error: Cant store ".$type->{'type'}." for ".$var.$val."($datarow->{'packetid'})");
							$data_raw->execute($datarow->{'packetid'}, $var.$val, 'Error');
						} elsif ($type->{'type'} eq "String"){
							syslog('warning', "Error: Cant store ".$type->{'type'}." for ".$var.$val."($datarow->{'packetid'})");
							$data_raw->execute($datarow->{'packetid'}, $var.$val, 'Error');
						} elsif ($type->{'type'} eq "Location"){
							if ($var eq 'L'){	# We only know how to deal with Locations of type L anything else is an error
								my $locID=0;
								if      ($val =~ /^([+-]?[0-9]+\.[0-9]+),([+-]?[0-9]+\.[0-9]+)$/){	# Lat,Lon
									$data_location->execute($datarow->{'packetid'}, $1, $2, undef); 
									$locID=$dbh->last_insert_id(undef, "ukhasnet", "data_location", undef);
								} elsif ($val =~ /^([+-]?[0-9]+\.[0-9]+),([+-]?[0-9]+\.[0-9]+),([+-]?[0-9]+\.?[0-9]*)$/){	# Lat,Lon, Alt
									$data_location->execute($datarow->{'packetid'}, $1, $2, $3); 
									$locID=$dbh->last_insert_id(undef, "ukhasnet", "data_location", undef);
								} elsif ($val =~ /^([+-]?[0-9]{5,}),([+-]?[0-9]{5,})$/){    			# integer Lat,Lon (Hacky for balloons)
									$data_location->execute($datarow->{'packetid'}, ($1/10000), ($2/10000), undef); 
									$locID=$dbh->last_insert_id(undef, "ukhasnet", "data_location", undef);
								} elsif ($val =~ /^([+-]?[0-9]{5,}),([+-]?[0-9]{5,}),([+-]?[0-9]+)$/){	# Integer Lat,Lon, Alt (Hacky for balloons)
									$data_location->execute($datarow->{'packetid'}, ($1/10000), ($2/10000), $3); 
									$locID=$dbh->last_insert_id(undef, "ukhasnet", "data_location", undef);
								} else {
									syslog('warning', "Error: Can't parse Location (".$var.$val.":".$datarow->{'packetid'}.")");
									$data_raw->execute($datarow->{'packetid'}, $var.$val, 'Error');
								}
								if ($locID>0){
									$getNodeFromPacket->execute($datarow->{'packetid'});
									if ($getNodeFromPacket->rows()==1){
										my $nodeRow=$getNodeFromPacket->fetchrow_hashref;
										$updateNodeLocation->execute($nodeRow->{'originid'},$locID);
										#print "Packet:" . $datarow->{'packetid'} .", LocationID: $locID, Node:".$nodeRow->{'originid'}."\n"; 
									} else {
										syslog('warning', "Error: Can't get node for packet: ".$datarow->{'packetid'});
									}
								}
							} else {	# if eq L
								syslog('warning', "Error: Cant store ".$type->{'type'}." for ".$var.$val."($datarow->{'packetid'})");
								$data_raw->execute($datarow->{'packetid'}, $var.$val, 'Error');
							}
						} elsif ($type->{'type'} eq "NULL"){
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
		$nodeLastPacket->finish();
		$addPacketRX->finish();
		$addPath->finish();
		$uploadUpdate->finish();
		$uploadFailed->finish();
		$getRawData->finish();
		$getField->finish();
		$getNodeFromPacket->finish();
		$data_float->finish();
		$data_location->finish();
		$updateNodeLocation->finish();
		$data_raw->finish();
		$dataProcessed->finish();
		$delRaw->finish();
		$dbh->disconnect();
		sleep (5) if ($loop && ($entries==0));
	} else { #if ($dbh)
		syslog('warning', "Error: Unable to connect to DB");
		sleep(60) if $loop;
	}
} #while($loop)

unlink $lock_file;
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
		syslog('warning', "Error(getNodeID): Matched more than one node for $origin");
		#while (my $nodeRow=$getNode->fetchrow_hashref){
		#	syslog('warning', "Error(getNodeID): Node $origin could be id: " . $nodeRow->{'id'});
		#}
	} else {
		$addNode->execute($origin);
		$nodeID=$dbh->last_insert_id(undef, "ukhasnet", "nodes", undef);
		syslog('info', "(getNodeID): Added Node $origin($nodeID)");
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
		syslog('warning', "Error(splitData): No Match for $data");
		return (-1,-1,$data);
	}
}
