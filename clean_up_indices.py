# -*- coding: utf-8 -*-
#
# Copyright (C) Bitergia
#
# This program is free software: you can redistribute it and/or modify it under the terms 
# of the GNU General Public License as published by the Free Software Foundation, either 
# version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY 
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
# PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this 
# program. If not, see <https://www.gnu.org/licenses/>.
#
# Authors:
#      Luis Cañas-Díaz <lcanas@bitergia.com>
#

import argparse
import certifi
import configparser
import json
import os

from google.cloud import storage, bigquery
from google.api_core import exceptions
from opensearchpy import OpenSearch
from opensearch_dsl import Search


def main():

    args = parse_args()    
    parameters = parse_configuration(args.configuration_file)
    os_client = os_connect(parameters)
    bq_client = bigquery.Client()

    for index_name in parameters['indices']:
        if not os_client.indices.exists(index=index_name):
            print("Index %s not found" % str(index_name))
            continue

        documents_count = os_client.count(index=index_name).get('count', 0)
        print("Index %s contains %d documents" % (str(index_name), documents_count))

        file_name = os_to_json(index_name, parameters['output_dir'],os_client)
        print("Index %s copied to local machine: file %s" %                
              (str(index_name), str(file_name)))
        
        json_to_bucket(parameters['bucket_name'], file_name, index_name)
        print("Index %s copied to bucket" % str(index_name))
        
        bq_table_id = parameters['gcp_project'] + "." + parameters['bq_dataset'] + "." + \
                index_name
        create_bq_table(bq_client, bq_table_id)

        uri = "gs://" + parameters['bucket_name'] + "/" + index_name
        rows = bucket_to_bq(bq_client, bq_table_id, uri)
        print("Index %s copied to BigQuery: %d rows" % (str(index_name), rows))

        if os.path.exists(file_name):
            os.remove(file_name)

def parse_args():
    """Parses positional argument with the configuration file. Returns object with the
    arguments.
    """
    parser = argparse.ArgumentParser(description='Copy data from GrimoireLab to BigQuery')
    parser.add_argument('configuration_file')
    return parser.parse_args()

def parse_configuration(file_name):
    """Parses the configuration file and extracts the required parameters: port, path, 
    user, password, output_dir, indices, scroll_size.

    Returns a dictionary containing the extracted parameters.
    """
    parameters = {}
    config = configparser.ConfigParser()
    config.read(file_name)    
    section = config['bap2bq']

    parameters['host'] = section['host']
    parameters['port'] = section['port']
    parameters['path'] = section['path']
    parameters['user'] = section['user']
    parameters['password'] = section['password']
    parameters['output_dir'] = section['output_dir']
    parameters['scroll_size'] = section['scroll_size']
    indices = section['indices']
    parameters['indices'] = indices.replace(' ','').split(',')
    parameters['bucket_name'] = section['bucket_name']
    parameters['gcp_project'] = section['gcp_project']
    parameters['bq_dataset'] = section['bq_dataset']

    return parameters

def os_connect(my_conf):
    """Creates an OpenSearch client object client using the provided configuration 
    parameters.
    
    Returns the established OpenSearch client object.
    """
    connection = "https://" + my_conf['user'] + ":" + my_conf['password'] + "@" + \
        my_conf['host'] + ":" + my_conf['port'] + "/" + my_conf['path']

    client = OpenSearch(
        hosts = [connection],
        http_compress = True, # enables gzip compression for request bodies
        # http_auth = auth,
        use_ssl = True,
        verify_certs = False, # FIXME
        ssl_assert_hostname = False,
        ssl_show_warn = False,
        ca_cert=certifi.where(),
        size = my_conf['scroll_size']
    )

    return client

def key_breaks_bigquery(key):
    """
    Returns True when the key creates issues when moving data to BigQuery.

    The common issue with the problematic fields is that they have incoherent type of 
    values in the indexes, so BigQuery is not able to ingest them.

    - gender: we started filtering out some of the gender_acc fields, but we are 
      seeing so many errors that we decide to drop all of them
    - fields that read special fields from the git log (typically in the Linux kernel)
      are also discarded, these are the ones with 'non_authored', 'signed_off' and 
      'tested_by'
    - 'tags' and 'label' excluded due to incoherent data type
    """
    PROBLEMATIC = ["gender", "non_authored", "signed_off", "tested_by", "co_authored",
                   "tags", "reported_by", "label", "reported_by"]

    breaks_bq = False

    for token in PROBLEMATIC:
        if key.find(token) >= 0:
            breaks_bq = True
            break

    return breaks_bq

def os_to_json(index_name, output_dir, opensearch_connection):
    """ This method extracts data from an OpenSearch index, converts it to JSON format, 
    and writes it to an individual JSON file. Returns the name of the file name as output.

    The format of the created JSON file must follow these rules:
      - everything is a string except lists
      - double quote instead of single quote
      - one line per document
    """
    s = None
    s = Search(using=opensearch_connection, index=index_name)

    output_file = output_dir + "/" + str(index_name)

    with open(output_file, 'w') as fd:
        for hit in s.scan():
            buffer = {}
            # Some keys are repeated if they are converted to lowercase,
            # so we overwrite them to get rid of them
            for key, value in hit.to_dict().items():
                if key_breaks_bigquery(key.lower()):
                    continue
    
                # first we convert everything to string
                if isinstance(value, list):
                    # we need to keep the lists as they are
                    buffer[key.lower()] = value
                else:
                    buffer[key.lower()] = str(value)
    
            str_buffer = json.dumps(buffer)
            fd.write(str_buffer + '\n')

    return output_file

def json_to_bucket(bucket_name, source_file_name, destination_blob_name):
    """ Uploads a json file to the bucket.
    """
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

def create_bq_table(client, table_id):
    """Creates table in BigQuery. Skip the exception if it already existed.
    """
    bq_table = bigquery.Table(table_id)
    try:
        table = client.create_table(bq_table)
    except exceptions.Conflict:
        pass

def bucket_to_bq(client, table_id, uri):
    """Copy content from a file in a Google bucket (given with the uri) to a BigQuery 
    table. It overwrites the content of the table and returns the number of rows written.
    """
    job_config = bigquery.LoadJobConfig(
        autodetect=True,
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
        write_disposition = 'WRITE_TRUNCATE'
    )
    
    load_job = client.load_table_from_uri(
        uri,
        table_id,
        location="US",  # Must match the destination dataset location.
        job_config=job_config
    )

    load_job.result()  # Waits for the job to complete.
    destination_table = client.get_table(table_id)

    return destination_table.num_rows

if __name__ == "__main__":
    main()