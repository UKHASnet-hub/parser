Applications and scripts for the UKHasnet Backend system
========================================================


ukhasnet.pl
-----------
script that parses uploaded telemetry lines into the other tables within
the database. The configuration for this script should be provided in
config.json which should be based on config-template.json

This script is designed to only run a single instance per backed database.
Running multiple copies could lead to bad things.

Required packages

