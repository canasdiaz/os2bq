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
    conf = read_configuration(args.configuration_file)
    client = connect(conf)
    bq_client = bigquery.Client()

    for i in conf['indices']:
        if not client.indices.exists(index=i):
            print("Index %s not found" % str(i))
            continue            
        
        output_file = read_and_write(i, conf['output_dir'],client)
        print("Index %s copied to local machine: file %s" %  (str(i), str(output_file)))
        
        copy_to_bucket(conf['bucket_name'], output_file, i)
        print("Index %s copied to bucket" % str(i))
        
        bq_table_id = conf['gcp_project'] + "." + conf['bq_dataset'] + "." + i
        create_bq_table(bq_client, bq_table_id)

        uri = "gs://" + conf['bucket_name'] + "/" + i
        rows = copy_to_bq(bq_client, bq_table_id, uri)
        print("Index %s copied to BigQuery: %d rows" % (str(i), rows))

        if os.path.exists(output_file):
            os.remove(output_file)

def parse_args():
    """
    """
    parser = argparse.ArgumentParser(description='Copy data from GrimoireLab to BigQuery')
    parser.add_argument('configuration_file')
    return parser.parse_args()


def read_configuration(file_name):
    """Parses the configuration file and extracts the required parameters: port, path, 
    user, password, output_dir, indices, scroll_size.

    Returns a dictionary my_conf containing the extracted parameters.
    """
    my_conf = {}
    config = configparser.ConfigParser()
    config.read(file_name)    
    section = config['clean']

    my_conf['host'] = section['host']
    my_conf['port'] = section['port']
    my_conf['path'] = section['path']
    my_conf['user'] = section['user']
    my_conf['password'] = section['password']
    my_conf['output_dir'] = section['output_dir']
    my_conf['scroll_size'] = section['scroll_size']
    indices = section['indices']
    my_conf['indices'] = indices.replace(' ','').split(',')
    my_conf['bucket_name'] = section['bucket_name']
    my_conf['gcp_project'] = section['gcp_project']
    my_conf['bq_dataset'] = section['bq_dataset']

    return my_conf

def connect(my_conf):
    """Creates an OpenSearch client object client using the provided configuration 
    parameters.
    
    Returns the established OpenSearch client object.
    """

    # Create the client with SSL/TLS enabled, but hostname verification disabled.

    connection = "https://" + my_conf['user'] + ":" + my_conf['password'] + "@" + my_conf['host'] + ":" + my_conf['port'] + "/" + my_conf['path']

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


def read_and_write(index_name, output_dir, conn):
    """ This method extracts data from specified OpenSearch indices, converts it to JSON
    format, and writes it to individual JSON files, one for each index.

    The output format must follow these rules:
      - everything is a string except lists
      - double quote instead of single quote
      - one line per document
    """

    s = None
    s = Search(using=conn, index=index_name)

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

def copy_to_bucket(bucket_name, source_file_name, destination_blob_name):
    """ Uploads a file to the bucket.
    """
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

def create_bq_table(client, table_id):
    """
    """
    bq_table = bigquery.Table(table_id)
    try:
        table = client.create_table(bq_table)
    except exceptions.Conflict:
        pass

def copy_to_bq(client, table_id, uri):
    """
    """
    # TODO(developer): Set table_id to the ID of the table to create.
    # table_id = "your-project.your_dataset.your_table_name"

    job_config = bigquery.LoadJobConfig(
        autodetect=True,
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
    )
    
    load_job = client.load_table_from_uri(
        uri,
        table_id,
        location="US",  # Must match the destination dataset location.
        job_config=job_config,
    )  # Make an API request.

    load_job.result()  # Waits for the job to complete.

    destination_table = client.get_table(table_id)
    return destination_table.num_rows

if __name__ == "__main__":
    main()
