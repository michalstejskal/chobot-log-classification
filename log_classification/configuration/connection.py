

database_uri = 'postgresql+psycopg2://{dbuser}:{dbpass}@{dbhost}/{dbname}'.format(
    dbuser='chobotdb',
    dbpass='chobotdb',
    # dbhost='docker.for.mac.localhost',
    dbhost='localhost',
    dbname='chobotdb',
    charset="utf8"
)

connection_port=5001
# connection_port=5000
