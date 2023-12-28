# Bitergia Analytics Platform to BigQuery tables

This script moves data from the Bitergia Analytics Platform to BigQuery tables. The 
transformation is as simple as possible, so the result tables are not as efficient as
they could be. Many fields are repeated as the origin format is a nosql database.

To run this script you need to set up a project in GCP and a VM with an associated
service key. Once this is ready follow the next steps:

1. Create a directory named 'configurations'
1. Create a configuration file based on the example included in the 
file 'configuration.EXAMPLE' 
1. Execute the bash script 'execute.sh'