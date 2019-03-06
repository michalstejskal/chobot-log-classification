from bo.models import Network
from configuration.app_config import db


def get_network(network_id):
    return Network.query.filter_by(network_id=network_id).first()


def add_network_parameter(parameter):
    db.session.add(parameter)
    db.session.commit()
    db.session.close()

