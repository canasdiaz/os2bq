import certifi
import configparser
import json

from opensearchpy import OpenSearch
from opensearch_dsl import Search


def main():

    conf = read_configuration('configuration')
    client = connect(conf)
    files_docs = read_and_write(conf,client)

    print("List of files created:")
    for t in files_docs:
        print("File %s: %d documents" % t )

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
    """

    # red flag with gender_acc: we started filtering out some of the gender_acc fields, but we are seeing so many errors that we decide to drop all of them
    # NONE_INSTEAD_OF_ZERO = ["owner_gender_acc","author_gender_acc","commit_gender_acc","user_data_gender_acc"]
    is_genderish = key.find("gender") > 0

    # fields that break bigquery due to the incoherent type they have
    NONE_INSTEAD_OF_EMPTY_LIST = ["tags"]
    NULL_INSTEAD_OF_EMPTY_LIST = ["non_authored_co_authored_by_multi_domains","co_authored_by_multi_domains","signed_off_by_multi_domains","non_authored_signed_off_by_multi_domains"]
    UNKNOWN = ["reported_by_multi_bots","label"]

    problematic = NONE_INSTEAD_OF_EMPTY_LIST + NULL_INSTEAD_OF_EMPTY_LIST + UNKNOWN

    breaks_bq = (key in problematic) or is_genderish

    return breaks_bq


def read_and_write(my_conf, conn):
    """ This method extracts data from specified OpenSearch indices, converts it to JSON
    format, and writes it to individual JSON files, one for each index.

    The output format must follow these rules:
      - everything is a string except lists
      - double quote instead of single quote
      - one line per document
    """

    files_created = []

    for i in my_conf['indices']:

        if not conn.indices.exists(index=i):            
            continue

        s = None
        s = Search(using=conn, index=i)

        output_file = my_conf['output_dir'] + "/" + str(i)

        cont = 0
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
                cont += 1

        files_created.append((output_file,cont))

    return files_created


if __name__ == "__main__":
    main()
