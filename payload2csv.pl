#!/usr/bin/perl -w
use strict;
use DBI();
use JSON::XS qw( decode_json);

# TODO we should get this as an argument
my $payload="EMF14";

# TODO this should be in the config and possible to override on the command line
my $outdir="/home/mike/www/csv";

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

my $dbh=0;


$dbh = DBI->connect("DBI:Pg:host=$config->{'database'}{'host'};database=$config->{'database'}{'database'}", $config->{'database'}{'user'},$config->{'database'}{'password'});
# Check we're connected to the DB
if ($dbh){
	$dbh->do("SET search_path TO ukhasnet");

	my $allUpload=$dbh->prepare("select name,time,packet,rssi from ukhasnet.upload left join ukhasnet.nodes on nodes.id=upload.nodeid where packet similar to ? order by time;");

# Start transaction so we get a consistant state ?

	$allUpload->execute("%" . $payload . "%");	# All packets with $payload
=pod
	open _OUT, ">".$outdir."/".$payload."_all.csv";
	print _OUT "gateway,time,packet,rssi\r\n";
	while (my $row=$allUpload->fetchrow_hashref){
		print _OUT $row->{'name'} . "," . $row->{'time'} . ",\"" . $row->{'packet'} . "\"," . $row->{'rssi'} . "\r\n";
	}
	close _OUT;

	$allUpload->execute("%," . $payload . "%");	# All packets repeated by $payload
	open _OUT, ">".$outdir."/".$payload."_repeated.csv";
	print _OUT "gateway,time,packet,rssi\r\n";
	while (my $row=$allUpload->fetchrow_hashref){
		print _OUT $row->{'name'} . "," . $row->{'time'} . ",\"" . $row->{'packet'} . "\"," . $row->{'rssi'} . "\r\n";
	}
	close _OUT;

	$allUpload->execute("%\\[" . $payload . "%");	# All packets originated by $payload	
	open _OUT, ">".$outdir."/".$payload."_originated.csv";
	print _OUT "gateway,time,packet,rssi\r\n";
	while (my $row=$allUpload->fetchrow_hashref){
		print _OUT $row->{'name'} . "," . $row->{'time'} . ",\"" . $row->{'packet'} . "\"," . $row->{'rssi'} . "\r\n";
	}
	close _OUT;
=cut
	# Variations to generate
	# Also lookup packets from node and generate GW:Path columns for each packet

	my $node2id=$dbh->prepare("select id from ukhasnet.nodes where name=?;");
	my $getPackets=$dbh->prepare("select id, sequence from ukhasnet.packet where originid=?;");
	my $dataFloat=$dbh->prepare("select dataid,data from ukhasnet.data_float left join ukhasnet.fieldtypes on fieldid=fieldtypes.id where packetid=? order by fieldid,position;");
	my $packetRX=$dbh->prepare("select packet_rx.id,to_char(packet_rx_time, 'YYYY-MM-DD') as date, to_char(packet_rx_time,'HH24:MI:SS') as time, name from ukhasnet.packet_rx left join ukhasnet.nodes on gatewayid=nodes.id where packetid=?;");
	my $pathRX=$dbh->prepare("select name from ukhasnet.path left join ukhasnet.nodes on nodeid=nodes.id where packet_rx_id=? order by position;");

	# Lookup the nodes ID
	$node2id->execute($payload);
	if ($node2id->rows() == 1){
		# Get ID for node named in $payload
		my $nodeRow=$node2id->fetchrow_hashref;
		my $nodeID=$nodeRow->{'id'};
		open _OUT, ">".$outdir."/".$payload."_packets.csv";

		# Print the heading
		print _OUT "sequence,data,gw:time:path,gw:time:path\r\n";

		# Get list of packets from the Node
		$getPackets->execute($nodeID);
		while (my $packet=$getPackets->fetchrow_hashref){
			print _OUT $packet->{'sequence'} . ",";

			# Get Data for this packet
			$dataFloat->execute($packet->{'id'});
			# $dataLocation->execute($packet->{'id'});
			if ($dataFloat->rows() >=1){	# or dataLocation->rows() >=1
				print _OUT "\"";
				my $lastdatatype="";
				while (my $data=$dataFloat->fetchrow_hashref){
					if ($lastdatatype eq $data->{'dataid'}){
						print _OUT ",";
					} else {
						print _OUT $data->{'dataid'};
					}
					print _OUT $data->{'data'};
					$lastdatatype = $data->{'dataid'};
				}
				#location
				print _OUT "\"";
			}

			$packetRX->execute($packet->{'id'});
			while (my $rx=$packetRX->fetchrow_hashref){
				print _OUT ",\"" . $rx->{'name'} . "|" . $rx->{'date'} .  "|" . $rx->{'time'};
				$pathRX->execute($rx->{'id'});
				my $r=0;
				while (my $path=$pathRX->fetchrow_hashref){
					if ($r++ == 0){
						print _OUT "|";
					} else {
						print _OUT "," 
					}
					print _OUT $path->{'name'};
				}
				print _OUT "\"";

			}
		
			print _OUT "\r\n";
		}
		close _OUT;
	} else {
		print "Unable to get ID for " . $payload . "\n";
	}


	$allUpload->finish();
}
$dbh->disconnect();
