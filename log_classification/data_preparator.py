import codecs

# from pygrok import Grok
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer

from custom_pygrok.pygrok import Pygrok
# unicode(s, "utf-8")

def parse_log_item(item, pattern):
    # print("parse log row")
    # print(pattern)
    # print("TYPEEEEEEEEEEE")
    # pattern = pattern.encode('unicode_escape')
    # pattern = pattern.decode('unicode_escape')
    # pattern = str(pattern)
    # print(type(pattern))
    # print(pattern)


    # print("############################")
    # pattern = '(%{DATE:datum})?\s*(%{TIME:cas})?\s*(%{WORD:status_kod})?\s*(%{IP:vzdalena_ip})?:(%{WORD:vzdaleny_port})?\s*(%{QS:cn})?\s*(%{WORD:request_method})?\s*\"(%{URIPATHPARAM:pozadovana_url})?\"\s*(%{QS:query_string})?\s*(%{IP:lokalni_ip})?:(%{WORD:lokalni_port})?\s*\"(%{JAVACLASS:server_name})?\"\s*HTTP(%{URIPATHPARAM:http_protokol})?\s*(%{INT:request_vel})?\s*(%{INT:responese_vel})?\s*(%{INT:zpracovani_cas})?\s*(%{QS:referer})?\s*(%{QS:user_agent})?\s*(%{QS:cookies})?\s*(%{WORD:ssl_protokol})?\s*(%{USERNAME:ssl_cipher_suit})?\s*(%{QS:certifikat})?\s*(%{DATA:status_spojeni})?\s*(%{INT:proces_id})?\s*(%{QS:soubor})?"'
    # pattern = '(%{USERNAME:datum})?\s*'
    # pattern = str(pattern, 'unicode_escape')
    grok = Pygrok(pattern)
    # grok = Grok(pattern)
    # res = grok.match(item)
    res = grok.search(item)
    print("parse done")
    print(res)
    return res

def convert_log_file_to_dictionary(file_path, log_pattern):
    with codecs.open(file_path, 'r') as data_file:
        data = data_file.read().strip().splitlines()
        print("1")
        print(len(data))
        data = data[:100]

        result = []
        keys = []
        for index, line in enumerate(data):
            if (index / len(data) * 100) % 10 == 0:
                print(str((index / len(data) * 100)) + '%')

            log_as_dict = parse_log_item(line, log_pattern)
            print(log_as_dict)
            if log_as_dict is not None:
                result.append(log_as_dict)
            else:
                print("LOG AS DICT IS NONE")

        print("2")
        print(len(result))

        if len(result) != 0:
            keys = result[0].keys()
        return result, keys


def prepare_raw_data(raw_data):
    data = pd.DataFrame(raw_data)

    # all strings to lowercase
    data = data.apply(lambda x: x.str.lower() if (x.dtype == 'object') else x)
    # remove special characters
    data = data.apply(lambda x: x.str.replace('[^A-Za-z\s]+', '') if (x.dtype == 'object') else x)
    # all numbers to character
    data = data.apply(lambda x: x.str.replace('\d+', '') if (x.dtype == 'object') else x)
    # drop empty
    data.dropna(how='all', inplace=True)

    columns = data.columns.tolist()
    for column in data.columns:
        if data[data[column] == ''].size == data.size:
            columns.remove(column)

    data = data[columns]
    print("3")
    print(len(data))
    x = data.to_string(header=False,
                       index=False,
                       index_names=False).split('\n')
    dataset = [','.join(ele.split()) for ele in x]
    return dataset, columns


def create_bigram(dataset):
    global tokenizer
    # tokenizer = CountVectorizer(analyzer='char_wb', ngram_range=(2, 2), min_df=1.0, max_df=1.0)
    tokenizer = CountVectorizer(analyzer='char_wb', ngram_range=(2, 2), min_df=5)
    print("tokenizer start")
    tokenizer.fit(dataset)
    print("tokenizer fit")
    return tokenizer.transform(dataset).toarray()


def prepare_data(file, pattern):
    data_as_dict, keys = convert_log_file_to_dictionary(file, pattern)
    global columns
    dataset, columns = prepare_raw_data(data_as_dict)
    bigram = create_bigram(dataset)
    print("tokenizer hotovo")
    return bigram


def prepare_log_row(row, pattern):
    row = row.decode("utf-8")
    row = parse_log_item(row, pattern)
    if row is not None:
        row_str = ""
        for key, value in row.items():
            if key in columns:
                row_str = row_str + str(value) + ","

        row_str.lower()
        row_str.replace('[^A-Za-z\s]+', '')
        row_str.replace('\d+', '')

        x = tokenizer.transform([row_str]).toarray()
        return x[0]
    return None



# file = "/Users/michalstejskal/git/chobot/src/network/chobot_log_classification/data/arp-access_log-20160605"
# pattern = '(%{DATE:datum})?\s*(%{TIME:cas})?\s*(%{WORD:status_kod})?\s*(%{IP:vzdalena_ip})?:(%{WORD:vzdaleny_port})?\s*(%{QS:cn})?\s*(%{WORD:request_method})?\s*\"(%{URIPATHPARAM:pozadovana_url})?\"\s*(%{QS:query_string})?\s*(%{IP:lokalni_ip})?:(%{WORD:lokalni_port})?\s*\"(%{JAVACLASS:server_name})?\"\s*HTTP(%{URIPATHPARAM:http_protokol})?\s*(%{INT:request_vel})?\s*(%{INT:responese_vel})?\s*(%{INT:zpracovani_cas})?\s*(%{QS:referer})?\s*(%{QS:user_agent})?\s*(%{QS:cookies})?\s*(%{WORD:ssl_protokol})?\s*(%{USERNAME:ssl_cipher_suit})?\s*(%{QS:certifikat})?\s*(%{DATA:status_spojeni})?\s*(%{INT:proces_id})?\s*(%{QS:soubor})?"'
# bigram = prepare_data(file, pattern)

# one_row = '2016-06-04	12:00:09	200	94.199.43.237:25689	"-"	GET	"/wwwstats/f"	"?p=105:1:0:::::"	10.245.8.60:443	"www.czechpoint.cz"	HTTP/1.1	592	28765	45877	"-"	"curl/7.19.7 (x86_64-suse-linux-gnu) libcurl/7.19.7 OpenSSL/0.9.8j zlib/1.2.7 libidn/1.10"	"-"	TLSv1	DHE-RSA-AES256-SHA	"-$-"	+	7961	"proxy:http://10.245.10.45/pls/apex/f?p=105:1:0:::::"'
# prepare_log_row(one_row, pattern)


