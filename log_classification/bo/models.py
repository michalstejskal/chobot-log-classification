from sqlalchemy import Column, Integer, ForeignKey, String
from sqlalchemy.orm import relationship
from configuration.app_config import db


class User(db.Model):
    __tablename__ = 'chobot_user'
    user_id = Column(Integer, primary_key=True)
    login = Column(String(64), unique=True)
    password = Column(String(32), unique=False)
    first_name = Column(String(64), unique=False)
    last_name = Column(String(64), unique=False)
    email = Column(String(64), unique=True)
    networks = relationship("Network", backref="networks")
    secret = Column(String(250), unique=False)


class Network(db.Model):
    __tablename__ = 'network'
    network_id = Column(Integer, primary_key=True)
    network_type_id = Column(Integer, unique=False)
    name = Column(String(64), unique=False)
    commit_id = Column(String(64), unique=False)
    docker_image_id = Column(String(64), unique=False)
    docker_container_id = Column(String(64), unique=False)
    status = Column(Integer, unique=False)
    connection_uri = Column(String(64), unique=False)
    docker_registry = Column(String(64), unique=False)
    api_key = Column(String(250), unique=False)
    api_key_secret = Column(String(250), unique=False)
    user_id = Column(Integer, ForeignKey("chobot_user.user_id"))
    user = relationship("User", back_populates='networks')
    parameters = relationship("NetworkParameter", backref='parameters')
    modules = relationship("Module", backref='modules', lazy="joined")


class Module(db.Model):
    __tablename__ = 'module'
    module_id = Column(Integer, primary_key=True)
    type = Column(Integer, unique=False)
    response_class = Column(String(64), unique=False)
    connection_uri = Column(String(64), unique=False)
    status = Column(Integer, unique=False)
    connection_uri_internal = Column(String(64), unique=False)
    api_key = Column(String(250), unique=False)
    network_id = Column(Integer, ForeignKey("network.network_id"))
    network = relationship("Network", back_populates='modules')


class NetworkParameter(db.Model):
    __tablename__ = 'network_parameter'
    network_parameter_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), unique=False)
    abbreviation = Column(String(64), unique=False)
    value = Column(String(1024), unique=False)
    network_id = Column(Integer, ForeignKey("network.network_id"))

    def __init__(self, name, abbreviation, value, network_id):
        self.name = name
        self.abbreviation = abbreviation
        self.value = value
        self.network_id = network_id



class NetworkType(db.Model):
    __tablename__ = 'network_type'
    network_type_id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=False)
    image_id = Column(String(64), unique=False)